	int i;
	int a = 0;
int main(){
	for(i = 0; i < 10; i++){
		if(i > 9){
			a = a - i;
		}
		else if(i > 8){
			a = a + a;
		}
		else{
			a = a + i;
		}
	}
	return a;
}	
