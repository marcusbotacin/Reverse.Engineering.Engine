int main(){
	int i;
	int a = 0;
	for(i = 0; i < 1000; i++){
		if(i%2 == 0){
			a = a + i;
		}

		else{
			a = a - i;
		}
	}
	return a;
}	
