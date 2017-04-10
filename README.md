# Peer to Peer Chat Client Server

Project for COMP3234 Computer Networks.
A simple client program supporting peer to peer connection and communication based on the course-defined protocol, 
with a naive GUI supported by Python.


### Prerequisites

Currently the program is only tested on Ubuntu 1604 with python version 3.5.2



## Getting Started

install python virtual enviroment
```
pip3 install virtualenv
```
set up virtual environment according to [this guide](http://python-guide-pt-br.readthedocs.io/en/latest/dev/virtualenvs/)

clone the project to local folder
```
git clone git@github.com:whcacademy/P2PChatServer.git
```

## Running the tests

Firstly, run the room server which is provided by course instructor.
```
./room_server_64 # depend on the OS
```

Then, test cases now are currently included by the spec in [spec.pdf](https://github.com/whcacademy/P2PChatServer/blob/master/2016-17-Programming-Project.pdf)

run 
```
python3 P2PChat.py localhost 32340 50000
```
Note that the last argument is the port number which is needed to change if multiple clients are initialized.

## Versioning

Try to use [SemVer](http://semver.org/) for versioning.

## Authors

* **WANG Haicheng** - *Initial work* - [Haicheng](https://github.com/whcacademy)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgments

* hash_function Source: [http://www.cse.yorku.ca/~oz/hash.html](http://www.cse.yorku.ca/~oz/hash.html)
