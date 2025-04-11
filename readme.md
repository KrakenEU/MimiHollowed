Inject mimikatz into a remote process using PE Hollowing technique.

This project is a continuation of the normal MimiLoader I have uploaded here:

https://github.com/KrakenEU/MimiLoader/

However, it is not relevant to know how that loader worked. This technique doesn't implement any ofuscation like the previous one (I leave it for the reader) because I'm thinking of giving it other uses.

DUMMY USAGE EXAMPLE (you can wrap any command in double quotes if it contains spaces)
                     
```
MimiHollowed.exe coffee "lsadump::trust /patch" coffee 
```

If you want to change the process you will inject to, you just have to change this variable DEFINED above main

![imagen](https://github.com/user-attachments/assets/edae71ab-17f0-47c1-b9f8-c6211bbeea13)

![imagen](https://github.com/user-attachments/assets/49681c4a-0186-4a11-b160-392f94ffa947)
