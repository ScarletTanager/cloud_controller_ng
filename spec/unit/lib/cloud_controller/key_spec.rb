require 'spec_helper'
require_relative '../../../../lib/cloud_controller/key'

module VCAP::CloudController
  describe Key do
    let(:passphrase1) { 'v1-encryption-passphrase' }
    # let(:salt) { Encryptor.generate_salt }
    let(:label) { 'v1' }

    it 'initializes the key to a generated value' do
      k = Key.new(label, passphrase1)
      # k = Key.new(label, passphrase1, salt)
      # expect(k.salt).to eql(salt)
      expect(k.label).to eql(label)
      expect(k.key).not_to eql(passphrase1)
    end
  end
end