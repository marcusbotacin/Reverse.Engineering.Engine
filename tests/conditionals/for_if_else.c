int main(){
	int i;
	int a = 0;
	for(i = 0; i < 1000; i++){
		if(i > 900){
			a = a - i;
		}
		else if(i > 800){
			a = a + a;
		}
		else{
			a = a + i;
		}
	}
	return a;
}	
