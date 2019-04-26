#include <signal.h> 
#include <unistd.h> 
#include <stdio.h> 
#include <stdlib.h>

void init(){
    setvbuf(stdin, 0LL, 2, 0LL);
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stderr, 0LL, 2, 0LL);
}

int d2i(){

	double a = 0;
	long long int* b = &a;

	puts("input:");
	scanf("%lf",&a);
	printf("%lx\n",*b);
	return 0;
}

int i2d(){
	long long int b = 0;
	double *a = &b;
	char buf[64]={0};

	puts("input:");
	read(0,buf,60);
	b = atoll(buf);
	printf("%.20g\n",*a);
	return 0;
}

int main(){
	init();
	char buf[10];
	while(1){
		puts("choice:");
		read(0,buf,2);
		if(buf[0]=='1'){
			d2i();
		}
		else if(buf[0]=='2'){
			i2d();
		}
		else{
			break;
		}
	}
	return 0;
}