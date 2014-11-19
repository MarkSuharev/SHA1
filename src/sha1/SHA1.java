package sha1;

public class SHA1 {

     
    /** ответ в виде блока из 20 слов*/
    public final static int DIGEST_SIZE = 20;


    private int[]  m_state;
    private long   m_lCount;
    private byte[] m_digestBits;
    private int[]  m_block;
    private int    m_nBlockIndex;

    public SHA1() {
      m_state = new int[5];
      m_block = new int[16];
      m_digestBits = new byte[DIGEST_SIZE];
      reset(); 
    };


    public void clear() {
      int i;
      for (i = 0; i < m_state.length; i++) 
        m_state[i] = 0;
      m_lCount = 0;
      for (i = 0; i < m_digestBits.length; i++) 
        m_digestBits[i] = 0;
      for (i = 0; i < m_block.length; i++) 
        m_block[i] = 0;
      m_nBlockIndex = 0;
    };  
 


    // some helper methods...

    final int rol(int nValue,
                 int nBits) {

      return ((nValue << nBits) | (nValue >>> (32 - nBits)));
    };

    final int blk0(int i) {
      return (m_block[i] = (rol(m_block[i],24) & 0xff00ff00) | 
                            (rol(m_block[i], 8) & 0x00ff00ff));
    };

    final int blk(int nI) {
      return (m_block[nI & 15] = rol(m_block[(nI +  13) & 15] ^ m_block[(nI + 8) & 15] ^
                                     m_block[(nI + 2) & 15] ^ m_block[nI & 15], 1));
    };

    final void r0(int data[],
                  int nV,
                  int nW, 
                  int nX ,
                  int nY,
                  int nZ,
                  int nI) {
      data[nZ] += ((data[nW] & (data[nX] ^ data[nY])) ^ data[nY]) +
                  blk0(nI) + 
                  0x5a827999 +
                  rol(data[nV] ,5);
      data[nW] = rol(data[nW], 30);
    };

    final void r1(int data[], 
                  int nV, 
                  int nW,
                  int nX, 
                  int nY, 
                  int nZ,
                  int nI) {
      data[nZ] += ((data[nW] & (data[nX] ^ data[nY])) ^ data[nY]) +
                  blk(nI) +
                  0x5a827999 + 
                  rol(data[nV] ,5);
      data[nW] = rol(data[nW], 30);
    };

    final void r2(int data[], 
                  int nV, 
                  int nW,
                  int nX, 
                  int nY, 
                  int nZ,
                  int nI) {
      data[nZ] += (data[nW] ^ data[nX] ^ data[nY]) +
                  blk(nI) +
                  0x6eD9eba1 +
                  rol(data[nV] ,5);
      data[nW] = rol(data[nW], 30);
    };

    final void r3(int data[], 
                  int nV, 
                  int nW,
                  int nX, 
                  int nY, 
                  int nZ,
                  int nI) {
      data[nZ] += (((data[nW] | data[nX]) & data[nY]) | (data[nW] & data[nX])) +
                  blk(nI) +
                  0x8f1bbcdc +
                  rol(data[nV] ,5);
      data[nW] = rol(data[nW], 30);
    };

    final void r4(int data[], 
                  int nV, 
                  int nW,
                  int nX, 
                  int nY, 
                  int nZ,
                  int nI) {
      data[nZ] += (data[nW] ^ data[nX] ^ data[nY]) +
                  blk(nI) +
                  0xca62c1d6 +
                  rol(data[nV] ,5);
      data[nW] = rol(data[nW], 30);
    };

    void transform() {
          
        int[] dd = new int[5];
        dd[0] = m_state[0];
        dd[1] = m_state[1];
        dd[2] = m_state[2];
        dd[3] = m_state[3];
        dd[4] = m_state[4];
        r0(dd, 0, 1, 2, 3, 4, 0); r0(dd, 4, 0, 1, 2, 3, 1);
        r0(dd, 3, 4, 0, 1, 2, 2); r0(dd, 2, 3, 4, 0, 1, 3);
        r0(dd, 1, 2, 3, 4, 0, 4); r0(dd, 0, 1, 2, 3, 4, 5);
        r0(dd, 4, 0, 1, 2, 3, 6); r0(dd, 3, 4, 0, 1, 2, 7);
        r0(dd, 2, 3, 4, 0, 1, 8); r0(dd, 1, 2, 3, 4, 0, 9);
        r0(dd, 0, 1, 2, 3, 4, 10); r0(dd, 4, 0, 1, 2, 3, 11);
        r0(dd, 3, 4, 0, 1, 2, 12); r0(dd, 2, 3, 4, 0, 1, 13);
        r0(dd, 1, 2, 3, 4, 0, 14); r0(dd, 0, 1, 2, 3, 4, 15);
        r1(dd, 4, 0, 1, 2, 3, 16); r1(dd, 3, 4, 0, 1, 2, 17);
        r1(dd, 2, 3, 4, 0, 1, 18); r1(dd, 1, 2, 3, 4, 0, 19);
        r2(dd, 0, 1, 2, 3, 4, 20); r2(dd, 4, 0, 1, 2, 3, 21); 
        r2(dd, 3, 4, 0, 1, 2, 22); r2(dd, 2, 3, 4, 0, 1, 23);
        r2(dd, 1, 2, 3, 4, 0, 24); r2(dd, 0, 1, 2, 3, 4, 25);
        r2(dd, 4, 0, 1, 2, 3, 26); r2(dd, 3, 4, 0, 1, 2, 27);
        r2(dd, 2, 3, 4, 0, 1, 28); r2(dd, 1, 2, 3, 4, 0, 29); 
        r2(dd, 0, 1, 2, 3, 4, 30); r2(dd, 4, 0, 1, 2, 3, 31);
        r2(dd, 3, 4, 0, 1, 2, 32); r2(dd, 2, 3, 4, 0, 1, 33); 
        r2(dd, 1, 2, 3, 4, 0, 34); r2(dd, 0, 1, 2, 3, 4, 35);
        r2(dd, 4, 0, 1, 2, 3, 36); r2(dd, 3, 4, 0, 1, 2, 37); 
        r2(dd, 2, 3, 4, 0, 1, 38); r2(dd, 1, 2, 3, 4, 0, 39);
        r3(dd, 0, 1, 2, 3, 4, 40); r3(dd, 4, 0, 1, 2, 3, 41); 
        r3(dd, 3, 4, 0, 1, 2, 42); r3(dd, 2, 3, 4, 0, 1, 43);
        r3(dd, 1, 2, 3, 4, 0, 44); r3(dd, 0, 1, 2, 3, 4, 45); 
        r3(dd, 4, 0, 1, 2, 3, 46); r3(dd, 3, 4, 0, 1, 2, 47);
        r3(dd, 2, 3, 4, 0, 1, 48); r3(dd, 1, 2, 3, 4, 0, 49); 
        r3(dd, 0, 1, 2, 3, 4, 50); r3(dd, 4, 0, 1, 2, 3, 51);
        r3(dd, 3, 4, 0, 1, 2, 52); r3(dd, 2, 3, 4, 0, 1, 53); 
        r3(dd, 1, 2, 3, 4, 0, 54); r3(dd, 0, 1, 2, 3, 4, 55);
        r3(dd, 4, 0, 1, 2, 3, 56); r3(dd, 3, 4, 0, 1, 2, 57); 
        r3(dd, 2, 3, 4, 0, 1, 58); r3(dd, 1, 2, 3, 4, 0, 59);
        r4(dd, 0, 1, 2, 3, 4, 60); r4(dd, 4, 0, 1, 2, 3, 61); 
        r4(dd, 3, 4, 0, 1, 2, 62); r4(dd, 2, 3, 4, 0, 1, 63);
        r4(dd, 1, 2, 3, 4, 0, 64); r4(dd, 0, 1, 2, 3, 4, 65); 
        r4(dd, 4, 0, 1, 2, 3, 66); r4(dd, 3, 4, 0, 1, 2, 67);
        r4(dd, 2, 3, 4, 0, 1, 68); r4(dd, 1, 2, 3, 4, 0, 69); 
        r4(dd, 0, 1, 2, 3, 4, 70); r4(dd, 4, 0, 1, 2, 3, 71);
        r4(dd, 3, 4, 0, 1, 2, 72); r4(dd, 2, 3, 4, 0, 1, 73); 
        r4(dd, 1, 2, 3, 4, 0, 74); r4(dd, 0, 1, 2, 3, 4, 75);
        r4(dd, 4, 0, 1, 2, 3, 76); r4(dd, 3, 4, 0, 1, 2, 77); 
        r4(dd, 2, 3, 4, 0, 1, 78); r4(dd, 1, 2, 3, 4, 0, 79);
        m_state[0] += dd[0];
        m_state[1] += dd[1];
        m_state[2] += dd[2];
        m_state[3] += dd[3];
        m_state[4] += dd[4];
    }


    /**
      * initializes or resets the hasher for a new session respectively
      */
    public void reset() {

      m_state[0] = 0x67452301;
      m_state[1] = 0xefcdab89;
      m_state[2] = 0x98badcfe;
      m_state[3] = 0x10325476;
      m_state[4] = 0xc3d2e1f0;
      m_lCount = 0;
      m_digestBits = new byte[20];
      m_nBlockIndex = 0;
    };


    /**
      * adds a single byte to the digest
      */
    public void update(byte bB) {

        int nMask = (m_nBlockIndex & 3) << 3;

        m_lCount += 8;
        m_block[m_nBlockIndex >> 2] &= ~(0xff << nMask);
        m_block[m_nBlockIndex >> 2] |= (bB & 0xff) << nMask;
        m_nBlockIndex++;
        if (m_nBlockIndex == 64) {
          transform();
          m_nBlockIndex = 0;
        };
    };

 
    /**
      * adds a byte array to the digest
      */
    public void update(byte[] data) {
     
      for (int nI = 0; nI < data.length; nI++)
        update(data[nI]);
    };
 

    /**
      * adds an ASCII string to the digest
      */
    public void update(String sData) {
     
      for (int nI = 0; nI < sData.length(); nI++)
        update((byte)(sData.charAt(nI) & 0x0ff));
    };
 
    public void finalize() {

        int i;
        byte bits[] = new byte[8];

        for (i = 0; i < 8; i++) {
          bits[i] = (byte)((m_lCount >>> (((7 - i) << 3))) & 0xff);
        };

        update((byte) 128);
        while (m_nBlockIndex != 56)
          update((byte) 0);

        for (i = 0; i < bits.length; i++)
          update(bits[i]);

        for (i = 0; i < 20; i++) {
          m_digestBits[i] = (byte)((m_state[i >> 2] >> ((3 - (i & 3)) << 3)) & 0xff);
        };
    };

    public String getResult(){
        String result = "";
        for(int i = 0; i < DIGEST_SIZE; i++){
            if(i!=0 && (i%4 == 0))
                result += " ";
            if( Integer.toHexString(m_digestBits[i]&0xFF).length() != 2)
                result += "0"+Integer.toHexString(m_digestBits[i]&0xFF);
            else
                result += Integer.toHexString(m_digestBits[i]&0xFF);
        }
        return result;
    }
}