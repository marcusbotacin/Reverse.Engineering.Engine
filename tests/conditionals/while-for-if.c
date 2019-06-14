int main(){
	int i,j;
	int a,b,c;
	a = 14;
	b = 5;
	c = a * b;
	if( c > 60){
		while( c != 60){
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
	
	
