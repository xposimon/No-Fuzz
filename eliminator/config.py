
PATH_CUT_INTERVAL = 2**7

# Block counts less than 5 times won't be considered,
# since they cannot affect the fuzzing too much.
# If a large branch execute a small number of times (<= 3),
# either it is extremely large which will not satisfy the developer
# or it can have limited effects on the fuzzing
BLK_HIT_THRESHOLD = 3

# Func with less than `SAME_HIT_BLKNUM_THRESHOLD` blks will be ignored,
# which can exist in real world program.
SAME_HIT_BLKNUM_THRESHOLD = 2*PATH_CUT_INTERVAL

ADDR_CHECK_NUM = 50
PATH_REMOVE_START_POS = 0
PATH_REMOVE_END_POS = 0