	int i,j;
	int a,b,c;
int main(){

	a = 14;
	b = 5;
	c = a * b;
	if( c > 6){
		while( c != 6){
			c--;
		}
	}
	for(i = 0; i < 10;i++){
		for(j = 0; j < 3;j++){
			c++;
		}
		c = c - a;
	}
	return c;
}
	
	
