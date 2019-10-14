##################################
## Scoring Configuration values ##
##################################

NUM_BITS_IN_CONST            = 32
MIN_STR_SIZE                 = 4
CONST_SPECIAL_VALUES         = [0xFFFFFFFF, -1]
CONST_BOOST_SPECIAL          = 4
CONST_BOOST_BIT_FLAG         = 6
CONST_BOOST_SMALL_FUNCS      = 4
CALL_COUNT_SCORE             = 7
MATCHED_CALL_SCORE           = 3
EXTERNAL_COUNT_SCORE         = 5
STRING_MATCH_SCORE           = 4
STRING_MISMATCH_SCORE        = 4
STRING_NAME_SCORE            = 5
INSTR_COUNT_SCORE            = 0.2
INSTR_COUNT_THRESHOLD        = 5
FUNC_FRAME_SCORE             = 0.1
FRAME_SIZE_THRESHOLD         = 32
FRAME_SAFETY_GAP             = 16
BLOCK_MATCH_SCORE            = 0.1
BLOCK_MISMATCH_SCORE         = 0.1
FUNC_HINT_SCORE              = 20
STATIC_VIOLATION_PENALTY     = 20
LOCATION_BOOST_SCORE         = 15
LOCATION_BOOST_LOW_THRESHOLD = 0.4
LOCATION_BOOST_TOP_THRESHOLD = 0.4
AGENT_BOOST_SCORE            = 20
EXISTENCE_BOOST_SCORE        = 5
MINIMAL_BLOCKS_BOOST         = 2
ARTIFACT_MATCH_SCORE         = 3
MINIMAL_MATCH_SCORE          = 18.5
SAFTEY_GAP_SCORE             = 10
MINIMAL_ISLAND_SCORE         = 0
MINIMAL_NEIGHBOUR_THRESHOLD  = -150
EXT_FUNC_MATCH_SCORE         = 25
LIBC_COMP_FUNC_MATCH_SCORE   = 20
LIBC_FUNC_MATCH_SCORE        = 10
INSTR_RATIO_COUNT_THRESHOLD  = 1
