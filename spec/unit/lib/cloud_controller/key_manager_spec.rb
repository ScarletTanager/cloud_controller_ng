require 'spec_helper'
require_relative '../../../../lib/cloud_controller/key_manager'
require_relative '../../../../lib/cloud_controller/key'

module VCAP::CloudController
  describe KeyManager do
     let(:pp1) { 'somepassphrase' }
     let(:pp2) { 'anotherpassphrase' }
     let(:pp3) { 'stillanotherpassphrase' }
     let(:ekey) { Key.new('1', pp1) }
     let(:dkeys) { {
       '2' => Key.new('2', pp2),
       '3' => Key.new('3', pp3) } }

    context 'Working with keys' do
      before do
        @km = KeyManager.new(ekey,dkeys)
      end
      it 'returns the right keys' do
        expect(@km.encryption_key).to eql(ekey)
        expect(@km.decryption_key('2')).to eql(dkeys['2'])
        expect(@km.decryption_key('3')).to eql(dkeys['3'])
      end
    end

    context 'Duplicate keys in configuration' do
      let(:pp1) { 'somepassphrase' }
      let(:pp2) { 'anotherpassphrase' }
      let(:pp3) { 'stillanotherpassphrase' }
      let(:ekey) { Key.new('1', pp1) }
      let(:dkeys) { {
        '1' => Key.new('1', pp1),
        '2' => Key.new('2', pp2),
        '3' => Key.new('3', pp3) } }

      it 'raises an exception if the encryption key also exists in the decryption key list' do
        expect {
          KeyManager.new(ekey, dkeys)
        }.to raise_error(RuntimeError)
      end
    end
  end
end