require 'openssl'

module VCAP::CloudController
  class Key
    @@iter = 20000
    @@key_len = 16

    class << self
      LABEL_MAX_LEN=32

      def label_maxlen
        LABEL_MAX_LEN
      end
    end

    attr_accessor :label

    def initialize(label, passphrase)
      raise if label.bytesize > Key.label_maxlen
      self.label=(label)
      @key = OpenSSL::HMAC.new(passphrase, OpenSSL::Digest.new('sha1')).to_s
    end

    def key
      @key
    end
  end
end