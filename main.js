(async () => {
  const SEAL = require("node-seal");
  // Step 1
  const setup = async () => {
    console.log("Participating as Alice");
    console.log(
      "=========================\nSTEP 1: Setup\n========================="
    );
    const seal = await SEAL();
    const schemeType = seal.SchemeType.bfv;
    const securityLevel = seal.SecurityLevel.tc128;
    const polyModulusDegree = 4096;
    const bitSizes = [36, 36, 37];
    const bitSize = 20;
    const encParms = seal.EncryptionParameters(schemeType);
    encParms.setPolyModulusDegree(polyModulusDegree);
    encParms.setCoeffModulus(
      seal.CoeffModulus.Create(polyModulusDegree, Int32Array.from(bitSizes))
    );
    encParms.setPlainModulus(
      seal.PlainModulus.Batching(polyModulusDegree, bitSize)
    );
    const context = seal.Context(
      encParms, // Encryption Parameters
      true,
      securityLevel
    );

    ////////////////////////////
    // Generate keys and shit //
    ////////////////////////////

    const keyGenerator = seal.KeyGenerator(context);
    const publicKey = keyGenerator.createPublicKey();
    const secretKey = keyGenerator.secretKey();

    // Create an Evaluator which will allow HE functions to execute
    const evaluator = seal.Evaluator(context);
    // Create a BatchEncoder (only BFV SchemeType)
    const encoder = seal.BatchEncoder(context);
    // Create an Encryptor to encrypt PlainTexts
    const encryptor = seal.Encryptor(context, publicKey);
    // Create a Decryptor to decrypt CipherTexts
    const decryptor = seal.Decryptor(context, secretKey);

    return [
      seal,
      {
        publicKey,
        secretKey,
        encryptor,
        decryptor,
        evaluator,
        encoder,
        context,
      },
    ];
  };
  const createSets = (n, m) => {
    // Function to generate an array of random numbers
    const generateRandomNumbers = (length) => {
      return Array.from({ length }, () => Math.floor(Math.random() * 1000) + 1);
    };
    const shuffleArray = (array) => {
      for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1)); // Get a random index from 0 to i
        [array[i], array[j]] = [array[j], array[i]]; // Swap elements
      }
      return array;
    };

    const firstArray = generateRandomNumbers(n);
    const secondArray = generateRandomNumbers(m);

    //forcing at least 1 intersection
    firstArray.push(6100);
    secondArray.push(6100);

    return [shuffleArray(firstArray), shuffleArray(secondArray)];
  };

  ///////////////////////////////
  // Change Length Params Here //
  ///////////////////////////////

  let n = 100; // alice set size
  let m = 10; // bob set size

  ////////////////////////////
  // Change Batch Size Here //
  ////////////////////////////

  let batch_size = 1;

  const [alice_array, bob_array] = createSets(n, m);
  const [seal_instance, homomorphic_enc_scheme] = await setup();

  // Step 2
  const alice_encrypt_elements = ({ alice_array, homomorphic_enc_scheme }) => {
    const { encryptor, encoder } = homomorphic_enc_scheme;
    // Change type of array to work with SEAL
    const set_alice = Int32Array.from(alice_array);
    // Save the length
    const set_alice_length = set_alice.length;

    // Encode Alice's set
    const set_plaintexts_alice = encoder.encode(set_alice);
    // Encrypt each element in Alice's set
    const set_ciphertexts_alice = encryptor.encrypt(set_plaintexts_alice);
    const set_ciphertexts_alice_string = set_ciphertexts_alice.save();
    return [
      set_ciphertexts_alice_string,
      set_ciphertexts_alice,
      set_alice_length,
    ];
  };
  const [
    set_ciphertexts_alice_string,
    set_ciphertexts_alice,
    set_alice_length,
  ] = alice_encrypt_elements({ alice_array, homomorphic_enc_scheme });

  // Step 3
  const bob_homomorphic_operations = (
    set_ciphertexts_alice_string,
    set_alice_length,
    elements_bob,
    seal_instance,
    homomorphic_enc_scheme
  ) => {
    const { evaluator, encoder, context } = homomorphic_enc_scheme;
    let seal = seal_instance;
    let final_products = [];
    let set_ciphertexts_alice = seal.CipherText();

    set_ciphertexts_alice.load(
      context,
      set_ciphertexts_alice_string,
      evaluator
    );

    // For the optimization, we split Bob's set into multiple subsets, each of size batch_size, for optimization
    const sets_plaintexts_bob = [];
    for (let i = 0; i < elements_bob.length; i += batch_size) {
      const batch = elements_bob.slice(i, i + batch_size);
      sets_plaintexts_bob.push(Int32Array.from(batch));
    }

    let counter = 0;
    sets_plaintexts_bob.forEach((set_plaintexts_bob) => {
      const final_product = seal.CipherText();

      // Homomorphically initialize result to first Alice's element - first Bob's element
      const first_element_bob = Int32Array.from(
        Array(set_alice_length).fill(set_plaintexts_bob[0])
      );
      const first_element_bob_encoded = encoder.encode(first_element_bob);
      evaluator.subPlain(
        set_ciphertexts_alice,
        first_element_bob_encoded,
        final_product
      );

      for (let i = 1; i < set_plaintexts_bob.length; i++) {
        const ith_element_bob = Int32Array.from(
          Array(set_alice_length).fill(set_plaintexts_bob[i])
        );
        const ith_element_bob_encoded = encoder.encode(ith_element_bob);
        const temp = seal.CipherText();
        evaluator.subPlain(
          set_ciphertexts_alice,
          ith_element_bob_encoded,
          temp
        );
        evaluator.multiply(final_product, temp, final_product);
      }

      let random_plaintext = new Int32Array(set_alice_length);
      crypto.getRandomValues(random_plaintext);
      const random_plaintext_encoded = encoder.encode(random_plaintext);
      evaluator.multiplyPlain(
        final_product,
        random_plaintext_encoded,
        final_product
      );

      const final_product_string = final_product.save();
      counter++;
      final_products.push(final_product_string);
    });

    return final_products;
  };
  let final_products = bob_homomorphic_operations(
    set_ciphertexts_alice_string,
    set_alice_length,
    bob_array,
    seal_instance,
    homomorphic_enc_scheme
  );
  // Step 4
  const alice_decrypt_intersection = (
    final_products,
    set_alice_length,
    seal_instance,
    homomorphic_enc_scheme
  ) => {
    let intersection_indexes = [];
    let counter = 1;

    const { decryptor, encoder, context } = homomorphic_enc_scheme;
    let seal = seal_instance;

    for (const final_product of final_products) {
      let final_product_ciphertext = seal.CipherText();
      final_product_ciphertext.load(context, final_product);
      const decrypted = decryptor.decrypt(final_product_ciphertext);
      const decoded = encoder.decode(decrypted);

      for (let i = 0; i < set_alice_length; i++) {
        if (decoded[i] == 0) {
          intersection_indexes.push(i);
        }
      }
      counter++;
    }

    console.log("Finished PSI calculation in\n");

    return intersection_indexes;
  };

  let intersection_indexes = alice_decrypt_intersection(
    final_products,
    set_alice_length,
    seal_instance,
    homomorphic_enc_scheme
  );

  const process_intersection_indexes = (
    intersection_indexes,
    aliceArray,
    bobArray
  ) => {
    if (intersection_indexes.length == 0) {
      console.log("no intersection womp womp");
      return;
    }

    console.log(`${intersection_indexes.length} common elements found`);

    let results = [];

    // Loop through intersection indexes to access aliceArray
    for (const index of intersection_indexes) {
      // Check if the index is within bounds
      if (index >= 0 && index < aliceArray.length) {
        let common_item = aliceArray[index];
        if (bobArray.includes(common_item)) {
          results.push(common_item);
        } else {
          console.log(
            "OH SHIT OH SHIT OH SHIT OH SHIT OH SHIT OH SHIT OH SHIT OH SHIT OH SHIT OH SHIT OH SHIT OH SHIT OH SHIT OH SHIT OH SHIT OH SHIT "
          );
        }
      }
    }
    console.log(results);

    return results;
  };
  process_intersection_indexes(intersection_indexes, alice_array, bob_array);
})();
