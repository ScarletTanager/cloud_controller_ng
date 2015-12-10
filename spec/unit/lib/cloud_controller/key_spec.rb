require 'spec_helper'
require_relative '../../../../lib/cloud_controller/key'

module VCAP::CloudController
  describe Key do
    let(:passphrase1) { 'v1-encryption-passphrase' }
    # let(:salt) { Encryptor.generate_salt }
    let(:label) { '1' }

    it 'initializes the key to a generated value' do
      k = Key.new(label, passphrase1)
      # k = Key.new(label, passphrase1, salt)
      # expect(k.salt).to eql(salt)
      expect(k.label).to eql(label)
      expect(k.key).not_to eql(passphrase1)
    end

    it 'raises an exception if the label exceeds 32 bytes in length' do
      longstring = "abcdefghijklmnopqrstuvwxyz"
      @label = ""
      for i in 0..2
        @label << longstring
      end

      expect { Key.new(@label, passphrase1) }.to raise_error(RuntimeError)
    end

    it 'returns the maximum label length' do
      expect(Key.label_maxlen).to be > 0
    end
  end
end