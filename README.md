# Summary of Changes
This repository contains the modifications we made to Checkpoint Research's library identification tool known as Karta. The work we did was done during the summer of 2019 at the MITRE Corporation. This work was approved for public release by MITRE. The bulk of our changes can be split into two parts: additional library identification support and Karta usage changes. We do not yet possess all of our files from MITRE and thus will be updating this repository as we receive we find them. 

Karta by Checkpoint Research was originally designed to extract open-source (and some closed-source) library usage information from closed-source programs in order to find vulnerable library usage. Karta uses the The Interactive Disassembler (IDA) to help it identify open-source libraries used and identify which functions in those libraries are called by the closed-source program.

We saw Karta’s unique capability to provide useful, automated analysis on malware samples. This analysis would give malware researchers insights into which combinations of libraries and library functions are used by different malware samples and provide a new vector for classifying and detecting malware.

As noted before, not everything mentioned here will be in the repository, we have not yet obtained some of our files from MITRE and are waiting for those to arrive. In order to allow for Karta to support the identification of additional open-source libraries, we needed to create additional models and python identification scripts. Models are essentially fingerprints of statically compiled open-source libraries, and were created through the use of Karta’s built-in analysis tools. The python identification scripts are very similar to the python scripts written by the original developer of Karta, Eyal Itkin, but are modified to search for different identifying features in each of the different open-source libraries. In order to add support for an entirely new library, a model and a python identification script are needed. However, in order to add support for another version of a library, only an additional model needs to be created. We added support for the open-source libraries libgcrypt, sqlite, and libpcap, and added additional version support for openSSL. 

The usage changes made to Karta were for the purpose of modifying it so that it could analyze massive amounts of malware samples in bulk. This meant writing a program to run IDA in “headless mode” and have it open malware samples, analyze them, and then run the Karta plugin to identify utilized open-source libraries before processing this output and recording the produced data. The final product produces a JSON file containing crucial information for each malware file analysed. This made it easy to compile statistics and quickly check the library usage for analysed malware samples. It also indicates the matching procedure used (more on that in the next paragraph), and if so, what versions and functions were matched or found. 

It would be foolish to compile an identification model and script for every single version of supported open-source libraries. Open-source libraries can have many alpha, beta, development and testing versions as well as several releases. Since they’re open-source, developers can compile the library whenever they want, for example between releases or alpha versions like after a certain pull request is accepted. Developers can also modify these open-source libraries to better fit their needs. While Karta does a good job recognizing functions and libraries even when a program is compiled by different compilers, Karta’s main purpose was to identify libraries versions. We believe the need to identify function usage is more important than the need to confirm the exact version of the library used when analysing malware samples. Therefore, we modified Karta to enable forced matching, a process where Karta will continue to try to verify the existence of a library with a nearby version and find library functions called even if it doesn’t have a model for the same exact version found in the version string of the library. We found that this significantly improves the results of running Karta on large malware datasets by finding versions of libraries where the version string may be non-existent but other identifying strings exist.

Thank you to The MITRE Corporation, Sarah Kern, and the NAIL labs for providing us with the resources and mentorship we needed to make this a successful project. We really enjoyed our internships last summer.
