# โครงสร้างธุรกรรมของบิตคอยน์ เข้าใจและเปิดเผยรายละเอียดภายใน

<br/>
เนื้อหาในบทความนี้จะให้ภาพรวมและรายละเอียดเกี่ยวกับโครงสร้างธุรกรรมของเงินสดดิจิทัลอย่างลึกซึ้ง ซึ่งจะช่วยให้คุณเข้าใจว่าเงินสดดิจิทัลทำงานอย่างไร


ธุรกรรมการใช้จ่ายเงินสดดิจิทัลจะถูก ยืนยันธุรกรรมโดย "นักขุด" ที่ทำงานอย่างหนัก และตรวจสอบเก็บรักษาโดย "โหนด" เป็นกลไกที่ใช้ในการเพิ่มความน่าเชื่อถือและความปลอดภัยให้กับข้อมูลธุรกรรมเหล่านั้น

เมื่อมีการทำธุรกรรมใหม่ ข้อมูลเกี่ยวกับธุรกรรมนั้นจะถูกรวบรวมเป็นหน้าบัญชี เมื่อ "นักขุด" ปิดบัญชีหรือการยืนยันขั้นสุดท้ายลงได้จะนำบัญชีนั้นไปต่อสมุดบัญชีหน้าถัดไปและนำสมุดบัญชีส่งต่อไปให้ "โหนด" อื่น ๆตรวจสอบต่อไป เรียกว่า "ไทม์เชน" (Time Chain)


สำหรับเนื้อหาบทความนี้เกี่ยวกับโครงสร้างธุรกรรมของบิตคอยน์ โดยเนื้อหาดังกล่าวจะสร้างความเข้าใจและทราบข้อมูลเชิงลึกรายละเอียดภายใน

ผมจะแบ่งเนื้อหาออกเป็น 4 ส่วนดังนี้
1. ส่วนแรกหรือก็คือบทความนี้ล่ะ ผมจะพูดในส่วนภาพรวมและองค์ประกอบคร่าว ๆ เป็นหลัก จะไม่เจาะลงลึกถึงขนาดว่าเขียนโค้ดอย่างไร แต่ละส่วนคำนวณแบบไหน แค่อธิบายให้เห็นในแต่ละส่วนมีอะไรบ้างเพียงเท่านั้น

2. มาทำความรู้จัก Public key ที่บิตคอยน์ใช้

3. สร้างลายเซ็นดิจิทัลด้วย ECDSA

4. ส่วนถัดไปผมจะลงลึกในการประกอบร่างสร้างธุรกรรมขึ้นมา ผมจะอธิบายอย่างละเอียดว่าแต่ละองค์ประกอบมันมาจากไหนคำนวณมาอย่างไร เพราะงั้นถ้าคุณทำตามที่ผมอธิบายไปคุณก็สามารถสร้างธุรกรรม หรือจะพูดว่าสร้าง UTxO เป็นของตัวเองได้ครับ

<br/>

_เอาล่ะ... ก่อนที่เราจะเข้าสู่เนื้อหาหลักของบทความนี้ เรามาทำความรู้จักกับ UTxO กันก่อนนะครับ
เพราะมันเป็นส่วนสำคัญในการทำงานของ Bitcoin ทำให้เห็นภาพรวมได้ง่ายขึ้น_

<br/>

## UTxO คืออะไร?

คำว่า "UTxO" ย่อมาจาก Unspent Transaction Output  ซึ่งหมายถึง เงินที่เรามีอยู่แต่เรายังไม่ได้ใช้จ่ายเงินนั้นออกไป
Output ของ UTxO หนึ่งเป็นการใช้จ่ายออกไปของคนหนึ่ง การใช้จ่ายของคนนั้นจะกลายเป็นรายรับของอีกคนหรือเป็น Input ของอีก UTxO ต่อไป

<br/>

![Group 100](https://github.com/rushmi0/Laeliax/assets/120770468/1f239976-cfad-405c-a77d-b3d368b75f91)

<br/>

ยกตัวอย่างง่าย ๆ ให้เห็นว่ามันเป็นยังไง (ไม่มีการคิดค่าธรรมเนียม)

ฟ้ามีเงินอยู่ 1 BTC .. ต้องการจะโอนเงินให้ส้ม 0.5 BTC
ฟ้าจะสร้าง ธุรกรรมขึ้นมา ขอเรียกว่า "Tx1" .. ในขาเข้า UTxO ของฟ้าจะมี 1 BTC

<br/>

![NUM 1](https://github.com/rushmi0/Laeliax/assets/120770468/b75902c6-fcae-4da3-ba58-337e774e1fb8)

<br/>

ขาออกจะมี 2 Output ออกมา จากที่เห็นจะ มีเงินของฟ้าโผล่ออกมาจาก UTxO นี้จำนวน 0.5 BTC
เป็นเพราะว่า ฟ้าโอนเงิน 0.5 BTC ให้กับส้ม .. พอฟ้าส่ง 0.5 BTC ให้กับส้มแล้ว ฟ้าจะได้เงินทอนให้ตัวเองกลับมา 0.5 BTC

<br/>

![NUM 3](https://github.com/rushmi0/Laeliax/assets/120770468/58cff0e0-46bc-4c6f-bd8c-575691659044)

<br/>

การใช้เงินบนพื้นฐาน UTxO จะต้องใช้จ่ายเงินทั้งหมดออกไป แล้วจะได้เงินทอนกลับมา (แอป Wallet จะสร้าง Address สำหรับรับเงินทอนเตรียมไว้อยู่แล้ว)
แบบนี้เราจะเห็นว่าผลรวม UTxO ขาเข้า จะต้องเท่ากับผลรวมของ UTxO ขาออกเสมอ (กรณีตัวอย่างนี้ไม่มีค่า Fee ของจริงจะมี UTxO แตกออกไปเป็นค่า Fee ด้วยครับ)

<br/>

![MIX TX](https://github.com/rushmi0/Laeliax/assets/120770468/08ac33ce-d9db-465d-8c33-88212859f86a)

<br/>

UTxO จะมี Input เท่าไหร่ก็ได้ และมี Output เท่าไหร่ก็ได้ เงินโอนเข้ามา 100 Address แล้วออกมา 200 Address .. หรือจะเข้ามา 5 Address ออกมา 5 Address ก็ได้

แต่ผลรวมของเงินในแต่ละ Address ทั้งขาเข้าและขาออก จะเท่ากันนะ
เป็นความสามารถหลอมรวม BTC เป็นหน่วยใหญ่และแตกเป็นหน่วยย่อย ๆ ก็ได้

<br/>


# โครงสร้างธุรกรรม
หลังจากที่เราทำเข้าใจเกี่ยวกับ UTxO กันแล้ว คุณจะเห็นว่าการโอนเงิน หรือการกระทำทางการเงินที่เกิดขึ้นระหว่างผู้ใช้งาน
โครงสร้างของ UTxO ประกอบด้วยสองส่วนหลัก ๆ คือ ขาเข้า (Input) และขาออก (Output)
ผลรวมของจำนวนเงิน "ขาเข้า" ต้องเท่ากับ "ขาออก"อย่างที่ผมอธิบายไป

การเขียนธุรกรรมใช้จ่ายเงินเราจะต้องน้ำ Tx ขาออก

<br/>


![UTxO Unsign](https://github.com/rushmi0/Laeliax/assets/120770468/128a9ad9-9160-4a58-b976-76cfff2513f5)

### ธุรกรรมดิบ ไม่มีลายเซ็น
```txt
0100000001cb1a50fbd2437ac064bd7306984d5fe2154c929e75b1ca0ea25261ceb13950c9000000002903abb915b1752102aa36a1958e2fc5e5de75d05bcf6f3ccc0799be4905f4e418505dc6ab4422a8dbacfdffffff0200c00b5a16000000160014342329383239d2f100a425ecf5112142e85ad10e0088526a740000001976a914977ae6e32349b99b72196cb62b5ef37329ed81b488acabb91500
```

![UTxO Sign](https://github.com/rushmi0/Laeliax/assets/120770468/df2b78eb-8bc9-4761-b37b-1a7f136f999e)

### ธุรกรรมดิบ มีลายเซ็น
```txt
0100000001cb1a50fbd2437ac064bd7306984d5fe2154c929e75b1ca0ea25261ceb13950c9000000007247304402201d04db63b2dd5bad68846dedc7f782c35f348183c4e10b8b04adb9ad4f575bd402200d4fcf862ddcb7bba8b875faac74fada81bfcf351182fcba22cdab8ea103c0ee012903abb915b1752102aa36a1958e2fc5e5de75d05bcf6f3ccc0799be4905f4e418505dc6ab4422a8dbacfdffffff0200c00b5a16000000160014342329383239d2f100a425ecf5112142e85ad10e0088526a740000001976a914977ae6e32349b99b72196cb62b5ef37329ed81b488acabb91500
```

สามารถนำธุรกรรมดิบเหล่านี้ไปเปิดดูได้ด้วยบิตคอยน์โหนดของเราเองได ้หรือเปิดดูด้วยเว็บ [blockchain.com](https://www.blockchain.com/explorer/assets/btc/decode-transaction)
