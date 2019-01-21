# axargs Usage

**快速实验**

```bash
echo "Hello 1" > hello1.txt
echo "Hello 2" > hello2.txt
echo "Hello 3" > hello3.txt

echo "hello1.txt\nhello2.txt\nhello3.txt" | xargs cat 
echo "hello1.txt\0hello2.txt\0hello3.txt" | xargs -0 cat

rm hello*.txt
```