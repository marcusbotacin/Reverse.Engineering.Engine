for i in `ls`; do
	for j in `ls $i/*.c`; do
		echo "Compiling "$j;
    		gcc $j -o ${j%.*}.bin;
	done
done
