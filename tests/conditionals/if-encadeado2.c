int main(){
	int a = 5;
	int b = 6;
	int c;
	c = a + b;
	if(c == 11){
		c = c -1;
		if(c != 10){
			c = 172; //nao entra
		}
		else{
			c = 474; //entra
		}	
	}
	return c;
}
