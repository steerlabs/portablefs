"""Honor an optional coordinator hold between native fixture cases."""
import os
import pathlib
import time


class NativeHoldRestartRequired(RuntimeError):
    pass


observed_hold = False


def hold_between_cases(restart_on_release=False):
    global observed_hold
    name = os.environ.get('PFS_NATIVE_HOLD_FILE')
    if not name:
        return
    path = pathlib.Path(name)
    announced = False
    while path.exists():
        observed_hold = True
        if not announced:
            print('HOLD: native fixture waiting between cases', flush=True)
            announced = True
        time.sleep(1)
    if restart_on_release and observed_hold:
        raise NativeHoldRestartRequired('HOLD invalidated the stateful native run; restart with a fresh guest')
    if announced:
        print('HOLD released: next native stage may start', flush=True)


if __name__ == '__main__':
    hold_between_cases()
