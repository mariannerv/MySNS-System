# Projeto Segurança
## Exemplo de comandos
### Compilar
- javac src/*.java -d bin
### Executar servidor
- java -cp bin mySNSServer 23456

### Executar cliente
- java -cp bin mySNS -a localhost:23456 -m mariana -p 123456 -u maria -sa testing1.txt

- java -cp bin mySNS -a localhost:23456 -m mariana -p 123456 -u marta -sc testing1.txt

- java -cp bin mySNS -a localhost:23456 -m mariana -p 123456 -u marta -se testing1.txt

- java -cp bin mySNS -a localhost:23456 -u marta -p 123456 -g testing1.txt

- java -cp bin mySNS -a localhost:23456 -au maria 123456 maria.cer 


### NOTAS
- Os ficheiros a serem usados devem estar dentro da pasta "ficheiros"; 
- A compilação e os restantes comandos devem ser executados dentro da diretoria "projeto1";
- A password atual do admin é "123456". Para alterar a password do admin basta apagar a pasta "admin" dentro da pasta "servidor" e reiniciar o servidor;
