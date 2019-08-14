#!/usr/bin/python3
__author__ = "Tim Carlisle, Jansen Moreno, Danielle Hughett, Joshua Pontes"
__copyright__ = "Copyright 2019, MurkSec"
__credits__ = ["Tim Carlisle", "Jansen Moreno", "Danielle Hughett", "Joshua Pontes"]
__license__ = "Proprietary"
__version__ = "1.0.1"
__maintainer__ = "MurkSec"
__email__ = "discord@discord.gg/e7d6Wwn"
__status__ = "Development"

#This project will follow the PEP 8 standard.
#https://realpython.com/python-pep8/
#https://www.python.org/dev/peps/pep-0008/

#import json
#import tkinter
#from tkinter import ttk
import csv
from enum import Enum, auto, unique
from checks import *

@unique
class ArtifactType(Enum):
    """
    This class is an enumeration class for the types of Artifacts.
    """
    AUTOSTART = auto()
    RAIR = auto()



class Artifact:
    """ 
    This class is used as a data storage for artifacts that are ingested from CSV files. 
      
    Attributes: 
        artifactType (ArtifactType): The artifact type as defined in class Atrifact Enum.
        timestamp (str): The timestamp of the artifact data...When it was scanned. Revisit: May need to change expected data type.
        threatScore (int): Numeric score in points on how dangerous artifact findings are.  0 is baseline.  Higher more dangerous, lower safer.
        data (dict):  The data from the scan in dict format.  Revisit later: this may end up being stored in JSON data.
    """

    def __init__(self, pArtifactType : ArtifactType, pData : dict):
        """ 
        The constructor for Artifact class. 
  
        Parameters: 
           pArtifactType (ArtifactType): : The artifact type as defined in class Artifact Enum.
           pData (dict):  The data from the scan in dict format.  Revisit later: this may end up being stored in JSON data. 
        """
        self.artifactType = pArtifactType 
        self.timestamp = ''
        self.threatScore = 0  
        self.data = pData    

class Match_Rule:
    """ 
    This class is the matching rules class. 
      
    Attributes: 
        dictionaryList (List): List of raw data broken into dictionary format loaded from CSV.
        Artifacts (List(ArtifactType)): The List of Artifact objects.
    """
    def __init__(self, pFunc : callable, pTargetArtifact : ArtifactType, pPoints : int):
        self.functionRef = pFunc
        self.targetArtifact = pTargetArtifact
        self.points = pPoints

class DRAS:
    """ 
    This class is the matching rules class. 
      
    Attributes: 
        dictionaryList (List): List of raw data broken into dictionary format loaded from CSV.
        Artifacts (List(ArtifactType)): The List of Artifact objects.
    """
    def __init__(self):
        self.stuff = "dumb"
        pass #this
        

#CSV File needs to be comma delimited, needs to be named in format:
#   YYYYMMDD-HHMMSS-customtitle-csvtype.csv
#need to change data hold to store indexes as artifact.
class DCC_CSV:
    """ 
    This class is the overarching container for individual CSV. 
      
    Attributes: 
        dictionaryList (List): List of raw data broken into dictionary format loaded from CSV.
        Artifacts (List(ArtifactType)): The List of Artifact objects.
    """
    def __init__(self, pCSVFile : str):
        """ 
        The constructor for Artifact class. 
  
        Parameters: 
           pCSVFile (pCSVFile): : The CSV file to be loaded.
        """
        self.dictionaryList = self.GenerateDictionaryFormat(self.PullCSV(pCSVFile))
        self.Artifacts = []
    
    def GetCSVInfo(self, pCSVFile : str) -> dict:
        """ 
        Parses CSV file name into pieces for data
  
        Parameters: 
           pCSVFile (pCSVFile): : The CSV file name to be parsed.
        Return:
            Dict:  Dict format of the parsed data from the CSV file name.   
        """
        data = {}
        filename = pCSVFile
        data['filename'] = filename
        data['year'] = filename[0:4]
        data['month'] = filename[4:6]
        data['day'] = filename [6:8]
        data['date'] = filename[0:8]
        data['hour'] = filename[8:10]
        data['minute'] = filename[10:12]
        data['second'] = filename[12:14]
        data['time'] = filename[8:14]
        data['timestamp'] = filename[0:14]
        data['title'] = filename.split('-')[1]
        data['artifacttype'] = filename.split('-')[2].split('.')[0]
        data['fileformat'] = filename.split('-')[2].split('.')[1]
        return data

    def IngestArtifacts(self, pCSVFile : str):
        """ 
        Ingests artifact data into data list.  This needs to possibly be refactored.
  
        Parameters: 
           pCSVFile (pCSVFile): : The CSV file name.
        Return:
            None 
        """
        data = self.GenerateDictionaryFormat(self.PullCSV(pCSVFile))
    
    def PullCSV(self, pCSVFile : str) -> list:
        """ 
        Pulls in data of CSV and returns the CSV data as a list of rows.
  
        Parameters: 
           pCSVFile (pCSVFile): : The CSV file name.
        Return:
            List of CSV data rows 
        """
        data = []
        with open(pCSVFile, newline='') as csvFile:
            fileReader = csv.reader(csvFile, delimiter=',')
            for row in fileReader:
                data.append(row)
        return data


    #The func template : GenerateDictionaryFormat(self, pCSVData : list) - > dict:
    #pCSVData is the data as generated from Pull CSV.
    #You need to parse off the first row of data as the fieldNames.  This will allow for any sort of CSV to be loaded.
    def GenerateDictionaryFormat(self, pCSVData : list) -> dict:
        """ 
        Takes CSV Data and arranges it into a dictionary and returns said dictionary.
        Note: This currently only works for one type of CSV.  Need to refactor to handle
        multiple types of CSV.
  
        Parameters: 
            pCSVData (List): The CSV Data.
        Return:
            Dict: The CSV Data in dict format.
        """

        outData = []
        fieldNames = pCSVData[0]
        for row in pCSVData[1:]:
            outDict = {}
            for x, element in enumerate(row):
                outDict[fieldNames[x]] = element
            outData.append(outDict)
        return outData

    def ReturnField(self, pFieldName : str) -> list:
        """ 
        Allows for the returning of a specified field in the form of a list from the data.
  
        Parameters: 
           pFieldName (str): Field Name.
        Return:
            List: List of all data from the field specified.
        """
        data = []
        for row in self.dictionaryList:
            data.append(row[pFieldName])
        return data

funcarray = [get_above_avg, get_below_avg]



tester2 = DCC_CSV("20190102112233-myscan-autoruns.csv")

for x in funcarray:
    print(x(tester2))
    #prolly not gonna work
#print(tester2.ReturnField('Version')[1])
#tester2.GetCSVInfo("20190102112233-myscan-autoruns.csv")



