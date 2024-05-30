mess1 = 'ABRACADABRA1235'
binary_mess1 = [bin(ord(mess1[i]))[2:] for i in range(len(mess1))]
print("Сообщение", mess1)
print("Бинарный вид сообщения")
for i in range(len(mess1)) : print(binary_mess1[i])

