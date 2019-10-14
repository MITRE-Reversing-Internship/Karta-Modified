from config.utils           import *
from disassembler.factory   import createDisassemblerHandler
from matching_engine        import KartaMatcher
from libs                   import lib_factory
import idaapi
from elementals import Logger
import logging
import json
import os
import subprocess
import ida_loader
#import cython
#from libc.stdio cimport FILE, fopen, fclose

######################
## Global Variables ##
######################
result={"approxLibs":[],"versions":{}}
config_path         = None      # path to the configuration directory (including the *.json files with the pre-compiled libraries)
logger              = None      # elementals logger instance

def startMatch(config_file, lib_name):
    """Start matching the wanted source library to the loaded binary.

    Args:
        config_file (path): path to the library's configuration file
        lib_name (str): name of the open source library
    """
    disas = getDisas()

    # always init the utils before we start
    initUtils(logger, disas, invoked_before=True)

    # Load the configuration file
    fd = open(config_file, 'r')
    config_dict = json.load(fd, object_pairs_hook=collections.OrderedDict)
    fd.close()

    # Load the accumulated knowledge for this binary file
    knowledge_config = loadKnowledge()
    manual_anchors = []
    if knowledge_config is not None and JSON_TAG_MANUAL_ANCHORS in knowledge_config:
        all_manual_anchors = knowledge_config[JSON_TAG_MANUAL_ANCHORS]
        if lib_name in all_manual_anchors:
            logger.debug("Loading manual anchors")
            logger.addIndent()
            for src_index in all_manual_anchors[lib_name]:
                src_file, src_name, hex_ea, bin_ea = all_manual_anchors[lib_name][src_index]
                logger.debug("Manual anchor: %s (%d), 0x%x", src_name, int(src_index), bin_ea)
                manual_anchors.append((int(src_index), bin_ea))
            logger.removeIndent()
    else:
        logger.debug("Has no manual anchors")

    # Init out matching engine
    matching_engine = KartaMatcher(logger, disas)

    try:
        # Load the source functions, and prepare them for use
        matching_engine.loadAndPrepareSource(config_dict[JSON_TAG_FILES])

        # Load and match the anchor functions
        matching_engine.loadAndMatchAnchors(config_dict[JSON_TAG_ANCHORS], manual_anchors)

        # Locate the file boundaries in the binary functions list
        matching_engine.locateFileBoundaries()

        # Prepare the located binary functions for first use
        matching_engine.prepareBinFunctions()

        # Now try to match all of the files
        matching_engine.matchFiles()

        # Generate the suggested function names
        ## matching_engine.generateSuggestedNames()
        # out of scope for now

        # Show the GUI window with the matches
       # match_entries, external_match_entries = matching_engine.prepareGUIEntries()
        ### This above function has potential for stuff that we can log. TODO add this to JSON file?

        logger.info("DEBUGGING PROCESS")
        
        result[lib_name]=matching_engine.debugPrintState()

        #matching_engine.showResultsGUIWindow(match_entries, external_match_entries)
    except KartaException:
        logger.error("Critical error, matching was stopped")

def matchLibrary(lib_name, lib_version):
    """Check if the library was already compiled, and matches it.

    Args:
        lib_name (str): name of the open source library
        lib_version (str): version string for the open source library that was found
    """
    # Check for existence
    result["versions"][lib_name]={"original":lib_version,"testedAgainst":lib_version}
    ##bit of a hack. this is to handle cases where there is force matching going on
    config_name = constructConfigPath(lib_name, lib_version)##TODO clean this up. could do with one less if statement
    cur_config_path = os.path.join(config_path, config_name)
    if not os.path.exists(cur_config_path):
        near=getNearbyVersion(lib_name,lib_version)
        if near==False:
            logger.error("Couldn't find config for %s",lib_name)
            #return
        cur_config_path=os.path.join(config_path,near[0])
        logger.warning("Forcing match for \"%s\". Original version \"%s\"",lib_name,lib_version)
       #result["approxLibs"].append(lib_name)
        result["versions"][lib_name]["testedAgainst"]=near
        if not os.path.exists(cur_config_path):
            logger.error("Missing configuration file (%s) for \"%s\" Version: \"%s\"",
                                    config_name, lib_name, lib_version)
            #return

    # Start the actual matching
    logger.addIndent()
    logger.info("Starting to match \"%s\" Version: \"%s\"", lib_name, lib_version)
    startMatch(cur_config_path, lib_name)
    logger.info("Finished the matching")
    logger.removeIndent()

def getNearbyVersion(lib_name,ogver):
    ### TODO
    ar=list(filter(lambda cf: lib_name in cf, list(os.walk(config_path))[0][2]))
    if len(ar)==0:
        return False
    winner=0
    for i in range(len(ar)):
        if len(os.path.commonprefix([ar[i],lib_name+"_"+ogver])) > len(os.path.commonprefix([ar[winner],lib_name+"_"+ogver])):
            winner=i
    return [ar[winner]]
    ##for now returns an almost random version, doesn't pay attention to numbers or significance of digits. TODO replace with some code that approximates nearby version

def matchLibraries():
    """Iterate over the supported libraries, and activates each of them."""
    # Load the accumulated knowledge for this binary file
    knowledge_config = loadKnowledge()
    if knowledge_config is not None and JSON_TAG_MANUAL_VERSIONS in knowledge_config:
        all_manual_versions = knowledge_config[JSON_TAG_MANUAL_VERSIONS]
    else:
        all_manual_versions = []
        logger.debug("Has no manual versions")
    libraries_factory = lib_factory.getLibFactory()
    for lib_name in libraries_factory:
        # create the instance
        lib_instance = libraries_factory[lib_name](disas.strings())
        # stopped when the first closed source shows up
        if not lib_instance.openSource():
            break
        # check for a pre-supplied manual version
        if lib_name in all_manual_versions:
            manual_versions = all_manual_versions[lib_name]
            logger.debug("Manual versions: %s", ", ".join(manual_versions))
        else:
            manual_versions = []
        logger.debug("Searching for library \"%s\" in the binary", lib_name)
        logger.addIndent()
        # search for it
        match_counter = lib_instance.searchLib(logger)
        # make sure we have a single match
        if match_counter > 1:
            logger.warning("Found multiple instances of \"%s\" - multiple instances are not supported right now", lib_name)
        elif match_counter == 0:
            logger.info("Did not find \"%s\" in the binary", lib_name)
            result[lib_name]={"id":False}
        # exact, single match
        else:
            logger.info("Successfully found \"%s\" in the binary", lib_name)
            # identify it's version
            lib_versions = lib_instance.identifyVersions(logger)
            # check if we need to identify this one
            result["versions"][lib_name]={}
            if lib_versions[0] == lib_instance.VERSION_UNKNOWN:
                if len(manual_versions) != 1:
                    """logger.warning("Forcing match for \"%s\". Original version unknown", lib_name)
                    #### TODO NOTE in this scenario, match to the nearest version?
                    result["approxLibs"].append(lib_name) ##intentionally not including version information, because the version string in and of itself cannot be trusted.
                    ## TODO: potential name collision if there's a library named "approxLibs"
                    ##continue           ##in this case, ID is true because it was identified, even though it WAS NOT MATCHED. Anyone parsing this should always check if error isset
                    manual_versions=getNearbyVersion(lib_name,"")
                    result["versions"][lib_name]={"testedAgainst":manual_versions[0]}
                    if(manual_versions==False):
                        continue
                    """
                    manual_versions=["UNKNOWN"]
                actual_version = manual_versions[0]
            else:
                actual_version = lib_versions[0]
            # now try to match the library
            ##if the version is forced, the version that will show up wil be the version of the model, not the one that was identified in the library
            try:
                matchLibrary(lib_name, actual_version) ## I need to figure out how to tell if this was successful, or at least how successful it is
            except Exception as e:
                logger.warning("Library matching failed")
                logger.warning(traceback.format_exc())
        # continue to the next library
        logger.removeIndent()

def checkWindows():
    """
    returns if the binary is windows or not. TODO
    """
    ## TODO: figure out what the output of File is when given a Windows binary
    ##TODO: [edit: (nevermind?), we're now passing args in a diff way?] escape shell args and prevent $() `` substitution!!! A maliciously crafted IDB or filename can cause problems!
    return "for MS Windows" in subprocess.check_output(["file",idaapi.get_input_file_path()]) ## NOTE: IDB's will preserve the path of the file from when the IDB was made. For example, Winston sent me a tcpdump i64, but he had generated it on windows. the I64 had the path of the file on windows, from root (not relative to the idb file at analysis-time)

def pluginMain():
    """Run the Karta (matcher) plugin."""
    global disas, logger, config_path

    # init our disassembler handler
    disas = createDisassemblerHandler(None)

    # Get the configuration values from the user
    config_values = {'is_windows':checkWindows(),'config_path':'/home/dhruv/Karta/configs'}
    #if config_values is None:
    #    return

    # store them / use them now for initialization
    config_path = config_values["config_path"]
    if config_values["is_windows"]:
        setWindowsMode()

    working_path = os.path.split(disas.databaseFile())[0]

    sourcename=os.path.split(idaapi.get_input_file_path())[1]

    log_files  = []
    #log_files += [(os.path.join(working_path, sourcename+"_debug.log"), "w", logging.DEBUG)]

    #for very large batches, maybe disable logging?
    #log_files += [(os.path.join(working_path, sourcename+"_info.log" ), "w", logging.INFO)]
    #log_files += [(os.path.join(working_path, sourcename+"_warning.log" ), "w", logging.WARNING)]
    ##open()
    ## in production, only save logs when problems occur
    logger = Logger(LIBRARY_NAME, log_files, use_stdout=False, min_log_level=logging.INFO)#replace with dummy?
    initUtils(logger, disas)
    logger.info("Started the Script")
    logger.info(sourcename)

    """if "Portable Executable" in ida_loader.get_file_type_name():
        ogfile=idaapi.get_input_file_path()
        if not os.path.exists(ogfile):
            ogfile=os.path.join(working_path,sourcename)
            ida_loader.gen_exe_file(fopen(ogfile,"w"))
        pe=pefile.PE(idaapi.get_input_file_path())
        for dirent in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if dirent.name and dirent.name.string==b"PYTHONSCRIPT":
                logger.info("Potentially a python executable!")
                result["python"]={id:true}
                break
    """

    # Active the matching mode
    setMatchingMode()

    # Init the strings list (Only once, because it's heavy to calculate)
    logger.info("Building a list of all of the strings in the binary")

    # Start matching the libraries
    logger.info("Going to locate and match the open source libraries")
    matchLibraries()

    # Finished successfully
    logger.info("Finished Successfully")

    # Notify the user about the logs
    logger.info("Saved the logs to directory: %s" % (working_path))    
    bulkfile=open(sourcename.replace("/","")+".analysis","w")
    bulkfile.write(json.dumps(result))
    ida_pro.qexit(0)

# Start to analyze the file
pluginMain()
