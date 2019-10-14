from lib_template import *
from config.utils import getDisas

class CryptoppSeeker(Seeker):
    """Seeker (Identifier) for the libpng open source library."""

    # Library Name
    NAME = 'cryptopp'
    # version string marker
    VERSION_STRING = "cryptopp_"

    # Overridden base function
    def searchLib(self, logger):
        """Check if the open source library is located somewhere in the binary.

        Args:
            logger (logger): elementals logger instance

        Return Value:
            number of library instances that were found in the binary
        """

        key_string = "0402FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE80289070FB05D38FF58321F2E800536D538CCDAA3D9"#this is  a point on a common ECC curve. Maybe this identifier will find all ECC crypto libs?
        backup_string = "041D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315"
        # Now search
        backup_strings = []
        self._version_strings = []
        for bin_str in self._all_strings:
            # we have a match
            if key_string in str(bin_str):
                copyright_string = str(bin_str)
                # check for the inner version string
                if self.VERSION_STRING not in copyright_string:
                    # false match
                    continue
                # valid match
                logger.debug("Located a copyright string of %s in address 0x%x", self.NAME, bin_str.ea)
                # save the string for later
                self._version_strings.append(copyright_string)
            # partial match, only the backup
            if backup_string in str(bin_str) and len(self._version_strings) == 0:
                # valid placeholder
                logger.debug("Located a place holder string of %s in address 0x%x", self.NAME, bin_str.ea)
                # save the string for later
                backup_strings.append(bin_str)

        # check if we need the backups
        if len(self._version_strings) == 0 and len(backup_strings) > 0 or True:
            clue_strings = []
            seen_funcs   = []
            disas = getDisas()
            # collect all of the strings that are referenced by the caller function
            for backup_string in backup_strings:
                for dref in disas.drefsTo(backup_string.ea):
                    caller_func = disas.funcAt(dref)
                    if caller_func is not None and caller_func not in seen_funcs:
                        # collect the strings
                        clue_strings += disas.stringsInFunc(disas.funcStart(caller_func))
                        # mark that we saw this function
                        seen_funcs.append(caller_func)
            # drop all illegal options
            clue_strings = filter(lambda x: self.extractVersion(x) == x, clue_strings)
            # the version will be the most popular string
            chosen_string = max(set(clue_strings), key=clue_strings.count)
            logger.debug("The chosen version string is: %s", chosen_string)
            self._version_strings.append(self.VERSION_STRING + chosen_string)

        # return the result
        return len(self._version_strings)

    # Overridden base function
    def identifyVersions(self, logger):
        """Identify the version(s) of the library (assuming it was already found).

        Assumptions:
            1. searchLib() was called before calling identifyVersions()
            2. The call to searchLib() returned a number > 0

        Args:
            logger (logger): elementals logger instance

        Return Value:
            list of Textual ID(s) of the library's version(s)
        """
        results = []
        self._version_strings = []
        self._version_strings.append("cryptopp820")
        # extract the version from the copyright string
        for work_str in self._version_strings:
            results.append(self.extractVersion(work_str, start_index=work_str.find(self.VERSION_STRING) + len(self.VERSION_STRING)))
        # return the result
        return results


# Register our class
CryptoppSeeker.register(CryptoppSeeker.NAME, CryptoppSeeker)
