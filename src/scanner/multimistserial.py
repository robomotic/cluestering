#!/usr/bin/env python
#-*- coding:utf-8 -*-
## ---------------------------------------------------------------
## multimistserial.py
## Converts serialized XML from CWSandbox to Malheur MIST format
## It can also learn the mapping from previous reports
## ---------------------------------------------------------------
## Author: Dr. Paolo Di Prodi ( paolo.diprodi@contextis.co.uk)
## License: LGPL
## ---------------------------------------------------------------
##
##    This file is part of Clustheur.
##
##    Clustheur is free software: you can redistribute it and/or modify
##    it under the terms of the GNU General Public License as published by
##    the Free Software Foundation, either version 3 of the License, or
##    (at your option) any later version.
##
##    Clustheur is distributed in the hope that it will be useful,
##    but WITHOUT ANY WARRANTY; without even the implied warranty of
##    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##    GNU General Public License for more details.
##
##    You should have received a copy of the GNU General Public License
##    along with Clustheur.  If not, see <http://www.gnu.org/licenses/>.

__author__="Paolo Di Prodi"
__version__="0.9"

import os
import string
import sys
import argparse
import pickle
import StringIO
import xml.dom.minidom as minidom



working_dir = os.path.dirname(__file__)

# Append path to local searhc path just in case!
package_dir = os.path.split(working_dir)[0]
package_dir = os.path.join(working_dir, "scanner")
sys.path.append(package_dir)

# This was described in the paper
CATEGORY_LOOKUP={"Windows COM":1,"DLL Handling":2,"Filesystem":3,"ICMP":4,"Inifile":5,"Internet Helper":6,"Mutex":7,
                    "Network":8,"Registry":9,"Process":10,"Windows Services": 11,"System":12,"Systeminfo":13,"Thread":14,
                    "User":15,"Virtual Memory":16,"Window":17,"Winsock":18,"Protected Storage":19,"Windows Hooks":20}
# This hashtable is what is learnt from previous reports
SYSCALL_LOOKUP={}

#default data folder for mist output
DIR_MIST="data/mist-output"
# verbose flag
verbose=0

def print_err(*args):
    sys.stderr.write(' '.join(map(str,args)) + '\n')
    
def lookup_syscal(category):
    for key in CATEGORY_LOOKUP.keys():
        if category.lower() in CATEGORY_LOOKUP[key].lower():
            return CATEGORY_LOOKUP[key]

def elf_hash (string):
    """ ELF hash used in the paper to encode filenames and other parameters """
    array=list(string)
    h=0
    g=None
    i=0
    
    for i in range(0,len(array)):
        h=( h << 4 ) + ord(array[i]);
        g = h & 0xf0000000L;
        if g!=0 :
            h ^= g >>24
        h&= ~ g
            
    return h

def scan_files(path,ext=None):
    """ list all the files in a path, non recursive """

    files = []
    if os.path.isdir(path):
        for root, dirs, filenames in os.walk(path):
            for name in filenames:
                rel_path=os.path.join(root, name)
                fileName, fileExtension = os.path.splitext(rel_path)

                if ext is None:
                    files.append(os.path.abspath(rel_path))
                elif fileExtension== ext:
                    files.append(os.path.abspath(rel_path))

    elif os.path.isfile(path):
        files.append(os.path.abspath(path))
    else:
        print_err( "You must supply a file or directory!")
        sys.exit()
        
    return files

def get_options_and_arguments(program_arguments):
    global verbose
    
    """ Builds and parse the program arguments and the help to print to console 
        :returns: list of arguments 
    """
    options, arguments = [], []

    parser=argparse.ArgumentParser(description="""Info: embed behavioural analysis from XML in a MIST report.\n
                                                                                            Example for learning: -l -m mist-reports/ xml_reports/ \n
                                                                                            Example for generating: -r xml_reports/ \n""",
                                    epilog="Copyright @ Contextis 2013 ")
                                    
    parser.add_argument('-l',"--learn", help="In learning mode you have to provide the MIST report folder as well", action='store_true')
    parser.add_argument('-r', "--report",help="In report mode reports will be produced from XML", action='store_true')
    parser.add_argument('-m',"--mist-folder",help="Folder containing MIST reports",type=str)    
    parser.add_argument('-v',"--verbose",help="Verbose mode",action='store_true')    
    parser.add_argument('file',help="A folder or a single file to convert or to learn from ",type=str)
    
    arguments=parser.parse_args(program_arguments)
        
    if not program_arguments:
        parser.print_help()  
        sys.exit(1)
        
    if not arguments.file:
        parser.error("File or directory path is missing!")  
        sys.exit(1)
                
    if arguments.verbose:
        print("Verbose mode is ON")
        verbose=1
        

    if arguments.report:
        xml_files=scan_files(arguments.file)
        if arguments.mist_folder:
            #generate the reports in the provided folder
            generate(xml_files,mist_folder)
        else:
            #make an output folder directory
            if not os.path.exists(DIR_MIST): 
                os.makedirs(DIR_MIST)
            else:
                generate(xml_files,DIR_MIST)
        
    if arguments.learn:
        xml_files=scan_files(arguments.file,".xml")
        if arguments.mist_folder:
            mist_files=scan_files(arguments.mist_folder)
            if len(xml_files)>0 and len(mist_files) >0:
                learn(xml_files,arguments.mist_folder)
            else:
                print_err("A folder is empty!")
        else:
            parser.error("Mist folder not provided!")
           
    return arguments

def parse_parameters():
    """
    Parse arguments and update PARAMETERS if needed
    """
    return get_options_and_arguments(sys.argv[1:])

    
def generate(xml_files,mist_folder):
    global SYSCALL_LOOKUP
    global verbose
    
    if os.path.exists('syscall_lookup.dat') is False:
        print_err("Lookup table is not present!")
        sys.exit(1)
        
    with open('syscall_lookup.dat', 'rb') as fp:
        SYSCALL_LOOKUP = pickle.load(fp)
    if verbose>0: print("Imported successfully")
        
    for file in xml_files:
        #initialize string
        mist_report = StringIO.StringIO()
        #manage dll behaviour:
        call_logs=[]
        xmldoc = minidom.parse(file)
        if verbose>0: print "Processing XML file ",file
        
        processes = xmldoc.getElementsByTagName('processes') 
        if len(processes)==1:
            #print itemlist[0].attributes['index'].value
            for process in processes[0].childNodes:
                if isinstance(process, minidom.Element):
                    if verbose>0: print "\tProcess ",process.attributes["index"].value
                    
                    thread_sections= process.getElementsByTagName("thread")
                    
                    for thread in thread_sections:
                        #TODO: can't understand the parameters here!
                        mist_report.write('# process 00000000 0000066a 022c82f4 00000000 thread 0001 #\n')
                        operations= thread.getElementsByTagName("all_section")
                        if len(operations)>0:
                            for operation in operations[0].childNodes:
                               if isinstance(operation, minidom.Element): 
                                if operation.tagName in SYSCALL_LOOKUP.keys():
                                    mist_report.write(' '.join(SYSCALL_LOOKUP[operation.tagName])+'|\n')
                                else:
                                    if verbose>0: print "No lookup for ",operation.tagName
    
        #output filename where to dump the report
        fileName, fileExtension = os.path.splitext(file)
        filePath=os.path.join(mist_folder,os.path.basename(fileName))
        
        with open(filePath,'w') as f:
            #get the whole string and write it
            f.write(mist_report.getvalue())
        
    
def learn(xml_files,mist_folder):
    global SYSCALL_LOOKUP
    global verbose
    
    #=================================
    # For each XML file scan it and convert it
    #=================================

    # for every file in the XML folder 
    for file in xml_files:
        #log every action in a call log list
        call_logs=[]
        xmldoc = minidom.parse(file)
        
        if verbose>0: print "Processing XML file ",file
        #find all the processes
        processes = xmldoc.getElementsByTagName('processes') 
        #there must be only one tag processes
        if len(processes)==1:
            #print itemlist[0].attributes['index'].value
            for process in processes[0].childNodes:
                if isinstance(process, minidom.Element):
                    if verbose>0: print "\tProcess ",process.attributes["index"].value
                    
                    thread_sections= process.getElementsByTagName("thread")
                    #examine every thread
                    for thread in thread_sections:
                        operations= thread.getElementsByTagName("all_section")
                        if len(operations)>0:
                            for operation in operations[0].childNodes:
                               if isinstance(operation, minidom.Element): call_logs.append(operation.tagName)
        else:
            print_err("XML format must contain only one tag processes")
            
        if len(call_logs)==0:
            print_err("XML file didn't contain any instructions...skipping")
            continue
        #now find the corresponding MIST file in the other folder
        fileName, fileExtension = os.path.splitext(file)
        filePath=os.path.join(mist_folder,os.path.basename(fileName))

        if os.path.exists(filePath):
        
            mist_lines = [line.strip() for line in open(filePath)]
            if verbose>0:
                print "\t\t Loaded %d MIST instructins" % len(mist_lines)
                print "\t\t Found %d serial instructins" % len(call_logs)
                
            # learn only level 1 MIST instructions
            level1=[]
            for instruction in mist_lines:
                #exclude comments and keep the rest
                if instruction[0]!='#':
                    #the default mist delimiter
                    levels=instruction.split("|")
                    #category of the syscall is the first number
                    category=levels[0].split(" ")[0].strip()
                    #the subcategory of the syscall is the second number
                    syscall=levels[0].split(" ")[1].strip()
                    # add tuples to the level 1 list as (category, syscall)
                    level1.append((category,syscall))
                    
            # time to do the mapping between MIST and XML actions
            # here unless my math is wrong there should be the same amount of MIST and XML actions!
            for index in range(0,len(level1)):
                if verbose>0:
                    print "Binding %s to (%s,%s)"%(call_logs[index],level1[index][0],level1[index][1])
                #simple hash table keeping the call log to the numeric MIST value
                SYSCALL_LOOKUP[call_logs[index]]=level1[index]        
        else:
            print_err("Cannot find corresponding MIST file ",filePath)
        
    # once the lookup table is totally full we dump it
    with open('syscall_lookup.dat', 'wb') as fp:
        pickle.dump(SYSCALL_LOOKUP, fp)
        if verbose>0: print "Saved syscall lookup"
        
def main():
    #=================================
    # Parse commandline arguments
    #=================================
    arguments = parse_parameters()

  
if __name__ == "__main__":
    main()
