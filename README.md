# Secure_Text_Editor
This is a project for the applied university of Dortmund.

## Getting Started

To start the editor, first install Maven here:
````https://maven.apache.org/install.html````

and make sure npm and node is installed. The download link is here:
```https://docs.npmjs.com/downloading-and-installing-node-js-and-npm```

then change to the secure-text-editor directory and start with the command
```mvn clean install```

then try to start the backend via
````mvn quarkus:dev````

after that open a new terminal and change to secure-text-editor-ui 

there you should run the command 

`````npm install`````

after the command is run start this command

`````npm start`````


## Java Code Coverage

use ````mvn clean test jacoco:report````
then under ``` /secure-text-editor/target/site/jacoco-resources``` there are the code reports!
