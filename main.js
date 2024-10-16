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
      return Array.from(
        { length },
        () => Math.floor(Math.random() * 10000) + 1
      );
    };

    const firstArray = generateRandomNumbers(n);
    const secondArray = generateRandomNumbers(m);

    //forcing at least 1 intersection
    firstArray.push(69);
    secondArray.push(69);

    return [firstArray, secondArray];
  };

  ///////////////////////////////
  // Change Length Params Here //
  ///////////////////////////////

  let n = 200; // alice set size
  let m = 200; // bob set size

  ////////////////////////////
  // Change Batch Size Here //
  ////////////////////////////

  let batch_size = 1;

  //const [alice_array, bob_array] = createSets(n, m);
  const [seal_instance, homomorphic_enc_scheme] = await setup();

  const alice_array = [
    "5550123",
    "5550456",
    "5550789",
    "5550423",
    "5551345",
    "5552345",
    "5551234",
    "5556789",
    "5557654",
    "5554567",
    "5558901",
    "5553456",
    "5550987",
    "5555678",
    "5558765",
    "5552134",
    "5554321",
    "5556543",
    "5550989",
    "5551199",
    "5558902",
    "5553457",
    "5551235",
    "5554320",
    "5552567",
    "5557890",
    "5551122",
    "5551500",
    "5559000",
    "5550255",
    "5550505",
    "5551100",
    "5556780",
    "5552200",
    "5553333",
    "5554444",
    "5555555",
    "5558888",
    "5551239",
    "5554712",
    "5551890",
    "5552109",
    "5554182",
    "5555120",
    "5550976",
    "5556098",
    "5551245",
    "5557894",
    "5556782",
    "5555670",
    "5553421",
    "5557865",
    "5555432",
    "5559087",
    "5552156",
    "5558163",
    "5556345",
    "5552342",
    "5557070",
    "5559813",
    "5553210",
    "5559191",
    "5555826",
    "5552423",
    "5557878",
    "5551111",
    "5555295",
    "5554333",
    "5559089",
    "5552121",
    "5552789",
    "5550975",
    "5551150",
    "5558800",
    "5554578",
    "5552032",
    "5553124",
    "5555624",
    "5557749",
    "5556429",
    "5558401",
    "5557525",
    "5554171",
    "5555444",
    "5553100",
    "5554359",
    "5556174",
    "5557709",
    "5552456",
    "5551188",
    "5557777",
    "5554888",
    "5559090",
    "5553377",
    "5556269",
    "5557222",
    "5554544",
    "5556943",
  ];

  const bob_array = [
    "5553001",
    "5552345",
    "5550423",
    "5551546",
    "5551890",
    "5557865",
    "5555670",
    "5550123",
    "5557456",
    "5558902",
    "5551390",
    "5551111",
    "5552222",
    "5558888",
    "5551199",
    "5554568",
    "5554001",
    "5550898",
    "5558945",
    "5552189",
    "5558900",
    "5553456",
    "5557654",
    "5559083",
    "5551220",
    "5550299",
    "5550398",
    "5554123",
    "5554567",
    "5558904",
    "5558271",
    "5555231",
    "5553498",
    "5550819",
    "5556667",
    "5559500",
    "5555779",
    "5550987",
    "5558299",
    "5559172",
    "5551119",
    "5559423",
    "5555258",
    "5553221",
    "5555890",
    "5557279",
    "5558101",
    "5550984",
    "5550000",
    "5555466",
    "5558520",
    "5557912",
    "5559057",
    "5551469",
    "5552706",
    "5559777",
    "5551871",
    "5554234",
    "5558364",
    "5553243",
    "5551021",
    "5556482",
    "5559150",
    "5556000",
    "5557777",
    "5550922",
    "5551114",
    "5553457",
    "5558791",
    "5554010",
    "5553045",
    "5556112",
    "5555448",
    "5559132",
    "5558270",
    "5557256",
    "5552500",
    "5558891",
    "5557023",
    "5558395",
    "5558225",
    "5552470",
    "5551800",
    "5559622",
    "5553921",
    "5551223",
    "5558963",
    "5557889",
    "5554851",
    "5556120",
    "5559270",
    "5559221",
    "5558481",
    "5557863",
    "5550384",
    "5551359",
    "5559523",
    "5550118",
  ];

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
        bobArray.includes(common_item)
          ? results.push(common_item)
          : console.log("fuck bob does not have it - something wrong");
      }
    }
    console.log(results);

    return results;
  };

  process_intersection_indexes(intersection_indexes, alice_array, bob_array);
})();
