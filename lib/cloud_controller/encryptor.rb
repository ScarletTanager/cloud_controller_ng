require 'securerandom'
require 'openssl/cipher'
require 'base64'
require_relative './key_manager'
require_relative './key'

module VCAP::CloudController::Encryptor
  class << self
    ALGORITHM = 'AES-128-CBC'.freeze
    IV_LEN = 16

    def configure(config)
      conf_key = 'crypto_keys'.to_sym
      return unless config.key?(conf_key)
      dkeys = Hash.new
      ekey = VCAP::CloudController::Key.new(
        config[conf_key][:encryption][:label],
        config[conf_key][:encryption][:passphrase]
      )

      config[conf_key][:decryption].each do |k|
        dkeys[k[:label]] = VCAP::CloudController::Key.new(
          k[:label],
          k[:passphrase]
        )
      end

      # TODO: add a rescue clause, KeyManager.new raises on key duplication
      self.key_manager=(VCAP::CloudController::KeyManager.new(ekey, dkeys))
    end

    def generate_salt
      SecureRandom.hex(4).to_s
    end

    def generate_iv
      OpenSSL::Random.random_bytes(IV_LEN)
    end

    def pack_format
      "CA" + VCAP::CloudController::Key.label_maxlen.to_s +
        "Ca" + IV_LEN.to_s + "Qa"
    end

    def encrypt_with_iv(input, salt, iv)
      return nil unless input
      return nil unless iv
      return nil unless key_manager

      cipher = make_cipher.encrypt

      cipher.key=(key_manager.encryption_key.key)
      cipher.iv=(iv)
      
      ciphertext = run_cipher(cipher, input, nil)

      pack_format = "CA" +
        VCAP::CloudController::Key.label_maxlen.to_s +
        "Ca" + IV_LEN.to_s + "Qa" + ciphertext.bytesize.to_s


      packed = [
        key_manager.encryption_key.label.bytesize,
        key_manager.encryption_key.label,
        iv.bytesize,
        iv,
        ciphertext.bytesize,
        ciphertext
      ].pack(pack_format)

      Base64.strict_encode64(packed)
    end

    def encrypt(input, salt)
      return nil unless input
      cipher = make_cipher.encrypt

      if key_manager then
        return encrypt_with_iv(input, salt, generate_iv)
      else
        cipher.pkcs5_keyivgen(db_encryption_key, salt)
      end 

      Base64.strict_encode64(run_cipher(cipher, input, salt))
    end

    def decrypt(encrypted_input, salt)
      return nil unless encrypted_input
      cipher = make_cipher.decrypt
      decoded = Base64.decode64(encrypted_input)

      if key_manager then
        fields = decoded.unpack(pack_format)
        ciphertext_len = fields[4]

        key_label = fields[1].strip
        if key_manager.decryption_key(key_label) != nil then
          cipher.key=(key_manager.decryption_key(key_label).key)
          cipher.iv=(fields[3])

          fields = decoded.unpack(pack_format + ciphertext_len.to_s)
          ciphertext = fields[5]
          return run_cipher(cipher, ciphertext, nil)
        end
      end

      cipher.pkcs5_keyivgen(db_encryption_key, salt)
      run_cipher(cipher, decoded, salt)
    end

    attr_accessor :db_encryption_key, :key_manager

    private

    def make_cipher
      OpenSSL::Cipher::Cipher.new(ALGORITHM)
    end

    def run_cipher(cipher, input, salt)
      cipher.update(input).tap { |result| result << cipher.final }
    end
  end

  module FieldEncryptor
    extend ActiveSupport::Concern

    module ClassMethods
      def encrypt(field_name, options={})
        field_name = field_name.to_sym
        salt_name = (options[:salt] || "#{field_name}_salt").to_sym
        generate_salt_name = "generate_#{salt_name}".to_sym
        storage_column = options[:column]

        unless columns.include?(salt_name)
          raise "Salt field `#{salt_name}` does not exist"
        end

        define_method generate_salt_name do
          return unless send(salt_name).blank?
          send "#{salt_name}=", VCAP::CloudController::Encryptor.generate_salt
        end

        if storage_column
          define_method field_name do
            send storage_column
          end

          define_method "#{field_name}=" do |value|
            send "#{storage_column}=", value
          end
        end

        define_method "#{field_name}_with_encryption" do
          VCAP::CloudController::Encryptor.decrypt send("#{field_name}_without_encryption"), send(salt_name)
        end
        alias_method_chain field_name, 'encryption'

        define_method "#{field_name}_with_encryption=" do |value|
          send generate_salt_name

          encrypted_value =
            if value.blank?
              nil
            else
              VCAP::CloudController::Encryptor.encrypt(value, send(salt_name))
            end

          send "#{field_name}_without_encryption=", encrypted_value
        end
        alias_method_chain "#{field_name}=", 'encryption'
      end
      private :encrypt
    end
  end
end
