# Projeto Segurança
## Example tests commands
### Compile
- javac src/*.java -d bin
### Execute server
- java -cp bin mySNSServer 23456

### Execute client
- java -cp bin mySNS -a localhost:23456 -m mariana -p 123456 -u maria -sa testing1.txt

- java -cp bin mySNS -a localhost:23456 -m mariana -p 123456 -u marta -sc testing1.txt

- java -cp bin mySNS -a localhost:23456 -m mariana -p 123456 -u marta -se testing1.txt

- java -cp bin mySNS -a localhost:23456 -u marta -p 123456 -g testing1.txt

- java -cp bin mySNS -a localhost:23456 -au maria 123456 maria.cer 
