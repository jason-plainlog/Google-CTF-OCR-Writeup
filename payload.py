from pwn import *
from math import log
from tqdm import tqdm
from PIL import Image, ImageDraw
import subprocess, threading

portion = 5

# data[row][col][channel] = {idx: val}, where idx is the index of image
data = [[[dict() for channel in range(3)] for col in range(16)] for row in range(16)]

def bruteforce(row, channel, pbar, lock):
    r = remote('ocr.2022.ctfcompetition.com', 1337)

    # solve proof of work challenge
    t = r.recvuntil(b'===================').decode().split('\n')
    challenge = list(filter(lambda x: 'python3' in x, t))[0].split(' ')[-1]
    ans = subprocess.check_output(
        ['python3', 'kctf-pow.py', 'solve', challenge], stderr=subprocess.DEVNULL)
    r.sendlineafter(b'Solution?', ans)

    # clear all weightes and biases
    r.sendlineafter(b'Menu:', b'0')

    # helper function to set weight: [layer, ..index.., weight]
    def setWeight(r, weight):
        r.sendlineafter(b'Menu:', b'1')
        r.sendlineafter(b'Type layer index, weight index(es), and weight value:', 
            b' '.join(list(map(lambda x: str(x).encode(), weight))))

    # set weight for softmax layer: layer 2, (0, 0) to 1
    setWeight(r, [2, 0, 0, 1])

    for col in range(16):
        idx = (row + 16 * col)*3 + channel
        setWeight(r, [0, idx, 0, 1])

        pre = None
        for i in range(1, 1 + portion):
            b = log(127) - 1 + (i / portion)
            setWeight(r, [1, 0, b])

            r.sendlineafter(b'3. Quit', b'2')
            r.recvuntil(b'sees:')
            res = r.recvline().split(b'\'')[1]
            res = eval(f"b'{res.decode()}'")
            res = [c == 0 for c in res]

            for cid, val in enumerate(res):
                if val and (pre is None or not pre[cid]):
                    data[row][col][channel][cid] = i
            pre = res

        lock.acquire()
        pbar.update(1)
        lock.release()

        setWeight(r, [0, idx, 0, 0])

    r.close()
    return

lock, pbar = threading.Lock(), tqdm(total = 16 * 16 * 3)

threads: list[threading.Thread] = []
for row in range(16):
    for channel in range(3):
        threads.append(threading.Thread(target=bruteforce, args=(row, channel, pbar, lock)))
        threads[-1].start()

for thread in threads:  thread.join()

# plot the image
images = [Image.new('RGB', (16*16, 16*16)) for _ in range(len(data[0][0][0]))]
for row in range(16):
    for col in range(16):
        for idx, image in enumerate(images):
            ImageDraw.Draw(image).rectangle(
                (16*row, 16*col, 16*(row+1), 16*(col+1)),
                tuple([data[row][col][chan][idx] * 255 // portion for chan in range(3)])
            )

for idx, image in enumerate(images):
    image.save(f'result/{idx}.png')

images[0].save('result.gif', save_all=True, append_images=images[1:], duration=1000, loop=0)
exit(0)
