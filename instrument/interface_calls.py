from lib import Call, CallConfig


"""
this file holds the logic to generate the call sequences for different 
enumeration tasks
"""


def gen_callconfig_onTransact(
    cmd_ids=list(range(0, 10)),
    repetitions=5,
    sleep_time=0.2,
    sleep_final=1,
    user="system",
):
    # iterate over some likely command ids, call each one a few times
    # should be straighforward since we only want to find the onTransact entrypoint
    calls = []
    for cmd_id in cmd_ids:
        for _ in range(0, repetitions):
            calls.append(Call(cmd_id, [], user=user))
    call_config = CallConfig(calls, sleep_time, sleep_final)
    return call_config


def gen_callconfig_find_cmd_ids(
    max=100, min=1, repetitions=1, sleep_time=0.2, sleep_final=1, user="system"
):
    calls = []
    for cmd_id in range(min, max):
        for _ in range(0, repetitions):
            calls.append(Call(cmd_id, [], user=user))
    call_config = CallConfig(calls, sleep_time, sleep_final)
    return call_config
