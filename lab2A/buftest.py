import string

def main():
    OUTPUT_PATH = "./buftest.txt"
    LEN = 2000
    print("A is %0x"%ord("A"))
    print("a is %0x"%ord("a"))
    print("0 is %0x"%ord("0"))
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    cnt = 0
    with open(OUTPUT_PATH, "w") as f:
        for i in lower:
            for j in upper:
                for k in range(10):
                    f.write(i)
                    cnt += 1
                    if cnt == LEN:
                        exit()
                    f.write(j)
                    cnt += 1
                    if cnt == LEN:
                        exit()
                    f.write(chr(ord('0')+k))
                    cnt += 1
                    if cnt == LEN:
                        exit()
    

if __name__ == "__main__":
    main()