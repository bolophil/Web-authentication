# Encryption

Will need docker and devcontainer in VScode installed.
Open with VScode.

This is implementing password hashing algorithms for a website. The files you will be editting include `/Areas/Identity/{Iterative,PBDKF2,BCrypt,Argon2Id}Hasher.cs`. 

## Running

* To run the server, use `dotnet run`. This will run the server.
* To view the sqlite database storing your users, use the visual studio command `SQLite: Open Database`. Then select the `app.db` file in the workspace directory. This will add a section on the left hand side of VSCode title `SQLITE EXPLORER`. From here you can click and look at the database tables.



