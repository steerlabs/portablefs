#!/usr/bin/env python3
"""Inspect a clock-run prefix without calling a partial 72-hour run a pass."""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import types

spec=importlib.util.spec_from_file_location('clock',pathlib.Path(__file__).with_name('qualify-linux-workspace-clock.py'))
clock=importlib.util.module_from_spec(spec)
spec.loader.exec_module(clock)


def inspect(root):
    status=json.loads((root/'status.json').read_text())
    raw=(root/'clock/samples.jsonl').read_bytes()
    lines=raw.splitlines(keepends=True)
    rows=[json.loads(v) for v in lines if v.endswith(b'\n')]
    campaign=json.loads((root/'clock/pause-campaign.json').read_text()) if (root/'clock/pause-campaign.json').exists() else dict(cases=[],errors=[])
    clock.attach_planned_windows(rows,types.SimpleNamespace(records=campaign['cases']))
    direct,ordinary,planned,passed,missing,violations=set(),set(),set(),set(),[],[]
    anchors=[]
    seen=set()
    for row in rows:
        slot=row['interval_slot']
        if slot is None: continue
        if slot in seen: violations.append('duplicate slot '+str(slot))
        seen.add(slot)
        if row['run_id']!=status['run_id']:violations.append('spliced run')
        reference=row.get('independent_reference')
        interval=None
        if reference:
            try:
                # Validate agreement at a point, before allowing a broader
                # sampling bracket to cover up authenticated disagreement.
                point=row['reference_ended_ns']
                clock.reference_interval(reference['references'],row['reference_began_ns'],point,point,point,reference.get('clock'))
                interval=clock.reference_interval(reference['references'],row['reference_began_ns'],point,
                                    row['sample_began_ns'],row['sample_ended_ns'],reference.get('clock'))
                direct.add(slot);anchors.append(point)
            except clock.BoundViolation as error:violations.append(str(error))
            except (KeyError,TypeError,ValueError) as error:missing.append(str(error))
        if row.get('planned_window'):
            planned.add(slot);continue
        ordinary.add(slot)
        if 'sample' not in row:
            missing.append('ordinary measurement absent: '+str(slot));continue
        try:
            check=clock.evaluate(row['sample'],interval)
            if check['source']=='pass':passed.add(slot)
            elif check['source']=='fail':violations.append('source bound: '+str(slot))
            else:missing.append('source inconclusive: '+str(slot))
        except clock.BoundViolation as error:violations.append(str(error))
        except (KeyError,TypeError,ValueError) as error:missing.append(str(error))
    elapsed=status.get('progress',{}).get('seconds',0)
    result=dict(run_id=status['run_id'],phase=status['phase'],elapsed_seconds=elapsed,
                samples=len(rows),unique_slots=len(seen),direct_reference_slots=len(direct),
                ordinary_measurements=len(ordinary),source_passes=len(passed),planned_unavailability_slots=len(planned),
                reference_fraction=len(direct)/len(seen) if seen else 0,
                maximum_anchor_gap_seconds=max(((b-a)/clock.SECOND for a,b in zip(anchors,anchors[1:])),default=0),
                pause_cases=len(campaign['cases']),pause_errors=campaign['errors'],missing=missing,violations=violations,
                first_read_source_passes=sum(v.get('first_read_source')=='pass' for v in campaign['cases']),
                raw_prefix_sha256=hashlib.sha256(raw).hexdigest(),raw_prefix_bytes=len(raw),
                qualification='incomplete; prefix health only')
    result['healthy_30_minutes']=(elapsed>=1800 and status['phase']=='running' and not status['errors']
                and not violations and not missing and not campaign['errors']
                and result['reference_fraction']>=.99 and result['maximum_anchor_gap_seconds']<=120
                and len(passed)==len(ordinary) and set(range(len(seen)))==seen
                and result['first_read_source_passes']==result['pause_cases'])
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('evidence',type=pathlib.Path)
    args=parser.parse_args();print(json.dumps(inspect(args.evidence),indent=2))
