Inject mimikatz into a remote process using PE Hollowing technique.

This project is a continuation of the normal MimiLoader I have uploaded here:

https://github.com/KrakenEU/MimiLoader/

However, it is not relevant to know how that loader worked. This technique doesn't implement any ofuscation like the previous one (I leave it for the reader) because I'm thinking of giving it other uses.

DUMMY USAGE EXAMPLE (you can wrap any command in double quotes if it contains spaces)
                     
```
MimiHollowed.exe coffee "lsadump::trust /patch" coffee 
```
