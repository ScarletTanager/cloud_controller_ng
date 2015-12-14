require 'spec_helper'
require_relative '../../../../lib/cloud_controller/key_manager'
require_relative '../../../../lib/cloud_controller/key'

module VCAP::CloudController
  describe Encryptor do
    let(:salt) { Encryptor.generate_salt }

    describe 'generating some salt' do
      it 'returns a short, random string' do
        expect(salt.length).to eql(8)
        expect(salt).not_to eql(Encryptor.generate_salt)
      end
    end

    describe 'encrypting a string' do
      let(:input) { 'i-am-the-input' }
      let!(:encrypted_string) { Encryptor.encrypt(input, salt) }

      it 'returns an encrypted string' do
        expect(encrypted_string).to match(/\w+/)
        expect(encrypted_string).not_to include(input)
      end

      it 'is deterministic' do
        expect(Encryptor.encrypt(input, salt)).to eql(encrypted_string)
      end

      it 'depends on the salt' do
        expect(Encryptor.encrypt(input, Encryptor.generate_salt)).not_to eql(encrypted_string)
      end

      it 'depends on the db_encryption_key from the CC config file' do
        allow(VCAP::CloudController::Encryptor).to receive(:db_encryption_key).and_return('a-totally-different-key')
        expect(Encryptor.encrypt(input, salt)).not_to eql(encrypted_string)
      end

      it 'does not encrypt null values' do
        expect(Encryptor.encrypt(nil, salt)).to be_nil
      end

      describe 'decrypting the string' do
        it 'returns the original string' do
          expect(Encryptor.decrypt(encrypted_string, salt)).to eq(input)
        end

        it 'returns nil if the encrypted string is nil' do
          expect(Encryptor.decrypt(nil, salt)).to be_nil
        end
      end

      context 'using crypto_keys in the configuration' do
        let(:km) { KeyManager.new(
          Key.new('v3', 'v3-encryption-key'),
              {
                'v2' => Key.new('v2', 'v2-encryption-key'),
                'v1' => Key.new('v1', 'v1-encryption-key'),
              }
            )
          }

        let(:iv) { Encryptor.generate_iv }

        before do
          allow(VCAP::CloudController::Encryptor).to receive(:key_manager).and_return(km)
          @cipher_text = Encryptor.encrypt_with_iv(input, salt, iv)
        end

        it 'decrypts a string encrypted with the legacy key' do
          expect(Encryptor.decrypt(encrypted_string, salt)).to eql(input)
        end

        it 'generates a unique IV of the correct length' do
          expect(iv.bytesize).to (eql(16))
          expect(Encryptor.generate_iv).not_to eql(iv)
        end

        it 'generates the correct pack format' do
          expect(Encryptor.pack_format).to eql(
            "CA" +
            Key.label_maxlen.to_s +
            "Ca16Qa"
          )
        end


        it 'encrypts using the current encryption key' do
          expect(@cipher_text).not_to eql(encrypted_string)
        end

        it 'decrypts using the correct decryption key' do
          expect(Encryptor.decrypt(@cipher_text, salt)).to eql(input)
        end
      end
    end
  end

  describe Encryptor::FieldEncryptor do
    let(:klass) do
      Class.new do
        include VCAP::CloudController::Encryptor::FieldEncryptor
      end
    end

    before do
      allow(klass).to receive(:columns) { columns }
      klass.send :attr_accessor, *columns # emulate Sequel super methods
    end

    describe '#encrypt' do
      context 'model does not have the salt column' do
        let(:columns) { [:id, :name, :size] }

        context 'default name' do
          it 'raises an error' do
            expect {
              klass.send :encrypt, :name
            }.to raise_error(RuntimeError, /name_salt/)
          end
        end

        context 'explicit name' do
          it 'raises an error' do
            expect {
              klass.send :encrypt, :name, salt: :foobar
            }.to raise_error(RuntimeError, /foobar/)
          end
        end
      end

      context 'model has the salt column' do
        context 'default name' do
          let(:columns) { [:id, :name, :size, :name_salt] }

          it 'does not raise an error' do
            expect {
              klass.send :encrypt, :name
            }.to_not raise_error
          end

          it 'creates a salt generation method' do
            klass.send :encrypt, :name
            expect(klass.instance_methods).to include(:generate_name_salt)
          end
        end

        context 'explicit name' do
          let(:columns) { [:id, :name, :size, :foobar] }

          it 'does not raise an error' do
            expect {
              klass.send :encrypt, :name, salt: :foobar
            }.to_not raise_error
          end

          it 'creates a salt generation method' do
            klass.send :encrypt, :name, salt: :foobar
            expect(klass.instance_methods).to include(:generate_foobar)
          end
        end
      end
    end

    describe 'field-specific methods' do
      let(:columns) { [:sekret, :sekret_salt] }
      let(:klass2) { Class.new klass }
      let(:subject) { klass2.new }
      let(:encryption_args) { {} }

      before do
        klass.class_eval do
          def underlying_sekret=(value)
            @sekret = value
          end

          def underlying_sekret
            @sekret
          end
        end
        klass2.send :encrypt, :sekret, encryption_args
      end

      describe 'salt generation method' do
        context 'salt is not set' do
          it 'updates the salt using Encryptor' do
            [nil, ''].each do |unset_value|
              expect(Encryptor).to receive(:generate_salt).and_return('new salt')
              subject.sekret_salt = unset_value
              subject.generate_sekret_salt
              expect(subject.sekret_salt).to eq 'new salt'
            end
          end
        end

        context 'salt is set' do
          it 'does not update the salt' do
            subject.sekret_salt = 'old salt'
            subject.generate_sekret_salt
            expect(subject.sekret_salt).to eq 'old salt'
          end
        end
      end

      describe 'decryption' do
        it 'decrypts by passing the salt and the underlying value to Encryptor' do
          subject.sekret_salt = 'asdf'
          subject.underlying_sekret = 'underlying'
          expect(Encryptor).to receive(:decrypt).with('underlying', 'asdf') { 'unencrypted' }
          expect(subject.sekret).to eq 'unencrypted'
        end
      end

      describe 'encryption' do
        it 'calls the salt generation method' do
          expect(subject).to receive(:generate_sekret_salt)
          subject.sekret = 'foobar'
        end

        context 'blank value' do
          it 'stores a default nil value without trying to encrypt' do
            expect(Encryptor).to_not receive(:encrypt)
            [nil, ''].each do |blank_value|
              subject.sekret = blank_value
              expect(subject.underlying_sekret).to eq nil
            end
          end
        end

        context 'non-blank value' do
          it 'encrypts by passing the value and salt to Encryptor' do
            subject.sekret_salt = 'asdf'
            expect(Encryptor).to receive(:encrypt).with('unencrypted', 'asdf') { 'encrypted' }
            subject.sekret = 'unencrypted'
            expect(subject.underlying_sekret).to eq 'encrypted'
          end
        end
      end

      describe 'alternative storage column is specified' do
        let(:columns) { [:sekret, :sekret_salt, :encrypted_sekret] }
        let(:encryption_args) { { column: :encrypted_sekret } }

        it 'stores the encrypted value in that column' do
          expect(subject.encrypted_sekret).to eq nil
          subject.sekret = 'asdf'
          expect(subject.encrypted_sekret).to_not eq nil
          expect(subject.sekret).to eq 'asdf'
        end
      end
    end
  end
end
