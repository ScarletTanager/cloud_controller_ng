require 'spec_helper'
require_relative '../../../../lib/cloud_controller/key_manager'
require_relative '../../../../lib/cloud_controller/key'

module VCAP::CloudController
  describe KeyManager do
     let(:pp1) { 'somepassphrase' }
     let(:pp2) { 'anotherpassphrase' }
     let(:pp3) { 'stillanotherpassphrase' }
     # let(:salt) { Encryptor.generate_salt }
     # let(:ekey) { Key.new(:v1, pp1, salt) }
     let(:ekey) { Key.new(:v1, pp1) }
     let(:dkeys) { {
       :v2 => Key.new(:v2, pp2),
       :v3 => Key.new(:v3, pp3) } }
       # :v2 => Key.new(:v2, pp2, salt),
       # :v3 => Key.new(:v3, pp3, salt)} }

    context 'Working with keys' do
      before do
        @km = KeyManager.new(ekey,dkeys)
      end
      it 'returns the right keys' do
        expect(@km.encryption_key).to eql(ekey)
        expect(@km.decryption_key(:v2)).to eql(dkeys[:v2])
        expect(@km.decryption_key(:v3)).to eql(dkeys[:v3])
      end
    end

    context 'Duplicate keys in configuration' do
      let(:pp1) { 'somepassphrase' }
      let(:pp2) { 'anotherpassphrase' }
      let(:pp3) { 'stillanotherpassphrase' }
      # let(:salt) { Encryptor.generate_salt }
      let(:ekey) { Key.new(:v1, pp1) }
      # let(:ekey) { Key.new(:v1, pp1, salt) }
      let(:dkeys) { {
        :v1 => Key.new(:v1, pp1),
        :v2 => Key.new(:v2, pp2),
        :v3 => Key.new(:v3, pp3) } }
        # :v1 => Key.new(:v1, pp1, salt),
        # :v2 => Key.new(:v2, pp2, salt),
        # :v3 => Key.new(:v3, pp3, salt)} }

      it 'raises an exception if the encryption key also exists in the decryption key list' do
        expect {
          KeyManager.new(ekey, dkeys)
        }.to raise_error(RuntimeError)
      end
    end
  end
end