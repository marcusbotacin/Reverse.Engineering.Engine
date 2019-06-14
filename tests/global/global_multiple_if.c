	int a = 0;
	int b = 14;
	int c;
	
int main(){

	c = a + b;
	if( c > 5){
		c = c + b;
	}
	if(a == 0){
		a = 247;
	}
	c = a - c + b;
	if(c < 100){
		c = 0; //dead code
	}
	if(c != 0){
		c = 5;
	}
	return c;
}
