# VTI-Cosplay
This project is designed to be a solution for the lack of the VirusTotal Hunting license(_YARA search capability_). It uses VirusTotal's _Content Search_ feature to simulate YARA scanning. 

Content Search is really helpful when someone would like to deepen its search across VirusTotal vast database. It is very similar to YARA. Certain byte patterns at a certain location can be easily searched. A YARA rule is contracted by a combination of patterns and conditions of them. So technically they are almost interchangeable. 

This project is YARA interpreter for the VirusTotal:
* Parsing the YARA rule 
* Creating queries for it
* Optimizing them to use less quota
* Making VirusTotal API requests
* Merging the results according to the rule's condition.

[![asciicast](https://asciinema.org/a/BMVqET0qPJ6didxzBMmMnAIgC.svg)](https://asciinema.org/a/BMVqET0qPJ6didxzBMmMnAIgC)
