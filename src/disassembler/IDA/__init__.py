try:
    from .ida_api       import *
except ImportError, e:
    print("Error importing IDA API")
    print(e)
from .ida_cmd_api       import *
