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

    attr_accessor :label, :key

    def initialize(label, passphrase)
      raise if label.bytesize > Key.label_maxlen
      self.label = label
      self.key = OpenSSL::HMAC.new(passphrase, OpenSSL::Digest.new('sha1')).to_s
    end
  end
end