require 'openssl'

module VCAP::CloudController
  class Key
    @@iter = 20000
    @@key_len = 16
    attr_accessor :label
    # attr_accessor :label, :salt

    def initialize(label, passphrase)
    # def initialize(label, passphrase, salt)
      # self.salt=(salt)
      self.label=(label)
      # @key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(passphrase, salt, @@iter, @@key_len)
      @key = OpenSSL::HMAC.new(passphrase, OpenSSL::Digest.new('sha1')).to_s
    end

    def key
      @key
    end

  end
end