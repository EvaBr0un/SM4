
all:	
	@echo  -e "\\n\\nUsage: make run -[MODE] -[REG] [DATA] [KEY]"
	@echo -e "\\t[MODE]:\\t  '-e'  - encrypting,   '-d' - decrypting"
	@echo -e "\\t[REG]:\\t  -ecb,  -ctr "
	@echo -e "\\t[DATA]:\\t - name of file/dirrectory for encrypting/decrypting"
	@echo -e "\\t[KEY]:\\t - name of binary file with your encrypting key\\n\\n"
	@echo -en "\033[37;1;42m The SM4 encryption program has been successfully installed! \033[0m \n"
	@gcc -c main.c
	@gcc -c SM4_block_encrypt.c
	@gcc -c SM4.c
	@ar cr libSM4.a SM4_block_encrypt.o SM4.o
	@gcc -o sm4 main.o libSM4.a

clean:
	@echo -en "\033[37;1;42m Clean \033[0m \n"
	@rm -f *.o *.a
