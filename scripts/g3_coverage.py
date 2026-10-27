"""G3 acceptance policy. Evidence absence never relaxes an error allocation."""
import bisect
import datetime
import json
import math
import pathlib

SECOND = 1_000_000_000
SLOT_NS = 30 * SECOND
FULL_SECONDS = 72 * 3600
POLICY = json.loads((pathlib.Path(__file__).parent/'nts-reference/policy.json').read_text())
OPERATORS = {host: operator for operator, hosts in POLICY['operators'].items() for host in hosts}
DURATIONS = (.1, .5, 2, 5, 15, 45, 150, 600)
MODES = ('normal', 'delayed', 'suppressed')


class BoundViolation(ValueError):
    pass


class ReferenceDisagreement(BoundViolation):
    pass


def inventory(blocks=12):
    """Identity, schedule and load phase, rather than an interchangeable count."""
    result = {}
    for block in range(blocks):
        cases = [(mode, pause) for mode in MODES for pause in DURATIONS]
        if block % 2:
            cases.reverse()
        for index, (mode, pause) in enumerate(cases):
            result[(block, mode, pause)] = 'idle' if index < 12 else 'load'
    return result


def campaign_coverage(records, errors):
    expected = inventory()
    seen, first, duplicate = set(), set(), set()
    problems = [v.get('error', str(v)) for v in errors]
    for record in records:
        case = record.get('case', {})
        key = (case.get('block'), case.get('fencing'), case.get('pause_seconds'))
        if key not in expected or key in seen:
            problems.append('duplicate or unexpected campaign identity: '+str(key))
            continue
        seen.add(key)
        trace = record.get('trace') or {}
        actual = trace.get('pause_confirmed_host_ns', -1)
        start = case.get('run_start_ns', 0)
        phase = (actual-start)//(3*3600*SECOND)
        if (case.get('load') != expected[key] or trace.get('load') != expected[key]
                or phase != key[0]*2+(expected[key]=='load')):
            problems.append('campaign load placement mismatch: '+str(key))
            continue
        if (trace.get('requested_pause_seconds')!=key[2] or trace.get('fencing')!=key[1]
                or not key[2] <= (trace.get('resume_requested_host_ns',-1)-actual)/SECOND < key[2]+1):
            problems.append('campaign duration/fencing trace mismatch: '+str(key))
            continue
        phase_evidence=trace.get('load_evidence',{})
        if (phase_evidence.get('load')!=expected[key]
                or phase_evidence.get('run_start_ns')!=start
                or phase_evidence.get('block')!=phase
                or (expected[key]=='load' and not phase_evidence.get('pid'))):
            problems.append('missing actual campaign load evidence: '+str(key))
            continue
        read = record.get('first_read', {})
        if (read.get('vm') == 'product' and read.get('operation_prestarted') is True
                and read.get('host_round_trip_after_resume') is False
                and type(read.get('generation')) is int
                and read.get('generation') == read.get('generation_after')
                and read.get('boot_id') == trace.get('boot_id')
                and read.get('sample_began_ns') == trace.get('resume_requested_host_ns')
                and record.get('first_read_source') == 'pass'):
            first.add(key)
        contention = record.get('duplicate_readers', {})
        if (contention.get('vm') == 'product' and contention.get('read_only') is True
                and contention.get('second_open_busy') is True
                and contention.get('readers', 0) >= 8 and contention.get('samples', 0) >= 8000
                and 0 <= contention.get('maximum_ns', -1) <= SECOND//4):
            duplicate.add(key)
    return dict(required=288, completed=len(seen), first_reads_completed=len(first),
                duplicate_cases_completed=len(duplicate), errors=problems,
                complete=seen == set(expected) and not problems,
                first_read_after_resume=first == set(expected) and not problems,
                concurrent_duplicate_readers=duplicate == set(expected) and not problems)


def propagate(anchor, target_begin, target_end, rho_ppm):
    """Propagate a bracketed anchor, retaining both endpoint alignments."""
    low, high = anchor['utc_interval_ns']
    begin, end = anchor['begin_ns'], anchor['end_ns']
    distance = max(abs(target_begin-end), abs(target_end-begin))
    expansion = math.ceil(distance*rho_ppm/1_000_000)
    return low+target_begin-end-expansion, high+target_end-begin+expansion


def coverage_verdict(records, start_ns, seconds, run_id, reference_interval, evaluate,
                     rate_envelope=None, disruptions=()):
    required = math.ceil(seconds/30)
    end_ns = start_ns+int(seconds*SECOND)
    slots, anchors, closing = {}, [], []
    failures, missing, invalid = [], [], list(disruptions)
    direct, bounded, ordinary, planned = set(), set(), set(), set()
    checks = []
    previous = start_ns-1
    for row in records:
        if not isinstance(row,dict) or type(row.get('reference_began_ns')) is not int:
            missing.append('missing/malformed observation timestamp');continue
        if row.get('observation') not in ('opening','ordinary','closing'):
            missing.append('missing/malformed observation kind')
        failures.extend(row.get('failures', []))
        if row.get('bound_violation'):
            failures.append(row.get('error', 'observed bound violation'))
        if row.get('run_id') != run_id or row.get('run_start_ns') != start_ns:
            invalid.append('spliced run identity or start epoch')
        began = row['reference_began_ns']
        if began <= previous:
            invalid.append('non-increasing observation timestamps')
        previous = began
        slot = (began-start_ns)//SLOT_NS
        if row.get('observation') == 'closing':
            closing.append(row)
            if began < end_ns:
                invalid.append('closing observation before run deadline')
        elif not 0 <= slot < required or row.get('interval_slot') != slot or slot in slots:
            invalid.append('duplicate, out-of-window or misassigned slot')
        else:
            slots[slot] = row
        row['reference_valid'] = False
        reference = row.get('independent_reference')
        if reference:
            try:
                point = row['reference_ended_ns']
                interval = reference_interval(reference['references'], began, point, point, point, reference.get('clock'))
                anchor = dict(begin_ns=point, end_ns=point, utc_interval_ns=interval, row=row)
                anchors.append(anchor)
                row['reference_valid'] = True
                if row.get('observation') != 'closing' and slots.get(slot) is row:
                    direct.add(slot)
            except ReferenceDisagreement as error:
                failures.append(str(error)); row['reference_valid'] = False
            except (KeyError, TypeError, ValueError) as error:
                row['reference_valid'] = False
                row['reference_error'] = str(error)
    selected={id(row) for row in slots.values()}
    for row in records:
        if not isinstance(row,dict) or (id(row) in selected and row.get('observation')!='closing'): continue
        try:
            if not row.get('sample'): missing.append('missing closing RTC observation'); continue
            interval=None
            if row.get('reference_valid'):
                ref=row['independent_reference']
                interval=reference_interval(ref['references'],row['reference_began_ns'],row['reference_ended_ns'],row['sample_began_ns'],row['sample_ended_ns'],ref.get('clock'))
            closing_check=evaluate(row['sample'],interval)
            if closing_check['source']=='fail': failures.append('closing source allocation violation')
            elif closing_check['source']!='pass': missing.append('inconclusive closing source interval')
        except BoundViolation as error: failures.append(str(error))
        except (KeyError,TypeError,ValueError) as error: missing.append('closing observation: '+str(error))
    anchors.sort(key=lambda a: a['begin_ns'])
    times = [v['begin_ns'] for v in anchors]
    opening = slots.get(0)
    endpoints = (opening is not None and opening.get('observation') == 'opening'
                 and opening.get('reference_valid') is True and len(closing) == 1
                 and closing[0].get('reference_valid') is True)
    if not endpoints:
        missing.append('direct opening/closing anchor')
    if any(b-a > 120*SECOND for a,b in zip(times,times[1:])):
        missing.append('anchor gap exceeds 120 seconds')
    # An independently supported pointwise rate envelope must be pinned before
    # the run. Endpoints and guest wall/BOOTTIME agreement cannot establish it.
    envelope_ok = (rate_envelope is not None and rate_envelope.get('independent') is True
                   and rate_envelope.get('support_sha256') and rate_envelope.get('pinned_before_start') is True
                   and 0 <= rate_envelope.get('rho_ppm', 501) <= 500)
    for slot, row in slots.items():
        if row.get('planned_window'):
            window = row['planned_window']
            if (window.get('verified') is True and window.get('run_id') == run_id
                    and window['begin_ns'] <= row['sample_ended_ns']
                    and window['end_ns'] >= row['sample_began_ns']):
                planned.add(slot)
                continue
            missing.append('unverified planned unavailability in slot '+str(slot))
        ordinary.add(slot)
        if 'sample' not in row or 'host_wall_pair' not in row:
            missing.append('missing ordinary measurement/bracket in slot '+str(slot)); continue
        interval = None
        method = 'direct'
        try:
            if row.get('reference_valid'):
                ref = row['independent_reference']
                interval = reference_interval(ref['references'], row['reference_began_ns'], row['reference_ended_ns'],
                                              row['sample_began_ns'], row['sample_ended_ns'], ref.get('clock'))
            elif envelope_ok:
                left = bisect.bisect_right(times, row['sample_began_ns'])-1
                right = bisect.bisect_left(times, row['sample_ended_ns'])
                if left >= 0 and right < len(anchors) and times[right]-times[left] <= 120*SECOND:
                    before = propagate(anchors[left], row['sample_began_ns'], row['sample_ended_ns'], rate_envelope['rho_ppm'])
                    after = propagate(anchors[right], row['sample_began_ns'], row['sample_ended_ns'], rate_envelope['rho_ppm'])
                    interval = max(before[0], after[0]), min(before[1], after[1])
                    if interval[0] > interval[1]:
                        raise ReferenceDisagreement('empty propagated UTC intersection')
                    method = 'bounded_gap'
            result = evaluate(row['sample'], interval)
            # Align the projected RTC interval to the bracketed host wall read;
            # this is diagnostic reconciliation, never a holdover-rate proof.
            pair=row['host_wall_pair']
            if (any(type(pair.get(k)) is not int for k in ('began_ns','ended_ns','wall_ns'))
                    or not pair['began_ns'] <= pair['ended_ns'] <= row['sample_began_ns']):
                raise ValueError('invalid host wall/monotonic bracket')
            post=row.get('host_wall_pair_after')
            if post:
                if not row['sample_ended_ns'] <= post['began_ns'] <= post['ended_ns']:
                    raise ValueError('invalid post-measurement host wall bracket')
                row['wall_monotonic_change_interval_ns']=(post['wall_ns']-pair['wall_ns']-(post['ended_ns']-pair['began_ns']),
                       post['wall_ns']-pair['wall_ns']-(post['began_ns']-pair['ended_ns']))
            rtc_low=datetime.datetime.fromisoformat(row['sample']['measurement']['rtc'].replace('Z','+00:00'))
            rtc_ns=int(rtc_low.timestamp())*SECOND + rtc_low.microsecond*1000 + result['measurement_age_ns']
            row['rtc_to_host_interval_ns']=(rtc_ns+pair['began_ns']-row['sample_ended_ns']-pair['wall_ns'],
                    rtc_ns+SECOND+result['sample_set_age_ns']+pair['ended_ns']-row['sample_began_ns']-pair['wall_ns'])
            if interval is not None:
                row['host_wall_to_nts_interval_ns']=(pair['wall_ns']-(interval[1]+pair['ended_ns']-row['sample_began_ns']),
                         pair['wall_ns']-(interval[0]+pair['began_ns']-row['sample_ended_ns']))
            row['checks'] = result
            row['source_method'] = method if interval is not None else 'unbounded'
            checks.append(result)
            if result['source'] == 'fail': failures.append('source allocation violation in slot '+str(slot))
            elif result['source'] != 'pass': missing.append('inconclusive source in slot '+str(slot))
            elif method == 'bounded_gap': bounded.add(slot)
        except BoundViolation as error:
            failures.append(str(error))
        except (KeyError, TypeError, ValueError) as error:
            missing.append('slot '+str(slot)+': '+str(error))
    if set(slots) != set(range(required)):
        missing.append('missing unique half-open slots')
    minimum = math.ceil(required*99/100)
    if len(direct) < minimum:
        missing.append('reference coverage below 99 percent')
    verdict = ('fail' if failures else 'inconclusive' if missing or invalid else 'pass')
    return dict(utc=verdict, failures=failures, missing=missing, invalid=invalid,
                unique_slots=len(slots), required_slots=required, minimum_reference_slots=minimum,
                direct_reference_slots=len(direct), bounded_gap_slots=len(bounded),
                ordinary_measurements=len(ordinary), planned_unavailability_slots=len(planned),
                source_passes=sum(v['source']=='pass' for v in checks), checks=checks,
                directly_referenced_endpoints=bool(endpoints), rate_envelope_supported=bool(envelope_ok))
