require "spec_helper"

RSpec.describe RubySnowflake::Client::KeyPairJwtAuthManager do
  let(:organization) { nil }
  let(:account) { "account" }
  let(:user) { "user" }
  let(:private_key) { OpenSSL::PKey::RSA.new(2048).to_pem }
  let(:jwt_token_ttl) { 3600 }
  let(:private_key_passphrase) { nil }
  
  subject { described_class.new(organization, account, user, private_key, jwt_token_ttl, private_key_passphrase) }

  describe "#jwt_token" do
    context "when creating a JWT token" do
      it "generates a valid token" do
        expect(subject.jwt_token).to be_a(String)
      end
      
      it "generates a token with the correct claims" do
        # Use the JWT gem to decode the token
        token = subject.jwt_token
        decoded_token = JWT.decode(token, OpenSSL::PKey::RSA.new(private_key).public_key, true, { algorithm: 'RS256' })[0]
        
        expect(decoded_token["iss"]).to include(account.upcase)
        expect(decoded_token["iss"]).to include(user.upcase)
        expect(decoded_token["sub"]).to eq("#{account.upcase}.#{user.upcase}")
        expect(decoded_token["iat"]).to be_a(Integer)
        expect(decoded_token["exp"]).to be_a(Integer)
      end
      
      it "creates token with proper expiration time" do
        now = Time.now.to_i
        token = subject.jwt_token
        decoded_token = JWT.decode(token, OpenSSL::PKey::RSA.new(private_key).public_key, true, { algorithm: 'RS256' })[0]
        
        # Expect the token to expire in approximately jwt_token_ttl seconds
        expect(decoded_token["exp"] - now).to be_within(5).of(jwt_token_ttl)
      end
    end

    context "when the private key is encrypted" do
      let(:private_key) do
        key = OpenSSL::PKey::RSA.new(2048)
        cipher = OpenSSL::Cipher.new("AES-128-CBC")
        key.to_pem(cipher, "password")
      end
      let(:private_key_passphrase) { "password" }

      it "generates a valid token" do
        expect(subject.jwt_token).to be_a(String)
      end

      it "generates a token with the correct claims" do
        # Use the JWT gem to decode the token
        token = subject.jwt_token
        decoded_token = JWT.decode(token, OpenSSL::PKey::RSA.new(private_key, private_key_passphrase).public_key, true, { algorithm: 'RS256' })[0]

        expect(decoded_token["iss"]).to include(account.upcase)
        expect(decoded_token["iss"]).to include(user.upcase)
        expect(decoded_token["sub"]).to eq("#{account.upcase}.#{user.upcase}")
        expect(decoded_token["iat"]).to be_a(Integer)
        expect(decoded_token["exp"]).to be_a(Integer)
      end
    end
  end
  
  describe "token caching" do
    let(:jwt_token_ttl) { 3540 }
    let(:minted_at) { Time.now.to_i }

    before { travel_to(minted_at) }

    def travel_to(seconds)
      allow(Time).to receive(:now).and_return(Time.at(seconds))
    end

    it "reuses the signed token rather than signing one per request" do
      subject.jwt_token

      expect(JWT).not_to receive(:encode)
      subject.jwt_token
    end

    it "keeps using it up to 80% of the token's life" do
      subject.jwt_token
      travel_to(minted_at + (jwt_token_ttl * 0.79).to_i)

      expect(JWT).not_to receive(:encode)
      subject.jwt_token
    end

    it "signs a new one past that point, while the old one is still valid" do
      subject.jwt_token
      travel_to(minted_at + (jwt_token_ttl * 0.8).to_i)

      expect(JWT).to receive(:encode).once.and_call_original
      subject.jwt_token
    end

    it "signs a new one once the token it holds has been rejected" do
      subject.jwt_token
      subject.expire_token!

      expect(JWT).to receive(:encode).once.and_call_original
      subject.jwt_token
    end

    it "does not go a whole TTL unsigned because one signing attempt failed" do
      allow(JWT).to receive(:encode).and_raise(JWT::EncodeError)
      expect { subject.jwt_token }.to raise_error(JWT::EncodeError)

      allow(JWT).to receive(:encode).and_call_original
      expect(subject.jwt_token).to be_a(String)
    end
  end

  describe "account_name handling" do
    context "when organization is nil" do
      let(:organization) { nil }
      
      it "uses only the account in the token" do
        token = subject.jwt_token
        decoded_token = JWT.decode(token, OpenSSL::PKey::RSA.new(private_key).public_key, true, { algorithm: 'RS256' })[0]
        
        expect(decoded_token["iss"]).to start_with("#{account.upcase}.")
        expect(decoded_token["sub"]).to eq("#{account.upcase}.#{user.upcase}")
      end
    end
    
    context "when organization is empty string" do
      let(:organization) { "" }
      
      it "uses only the account in the token" do
        token = subject.jwt_token
        decoded_token = JWT.decode(token, OpenSSL::PKey::RSA.new(private_key).public_key, true, { algorithm: 'RS256' })[0]
        
        expect(decoded_token["iss"]).to start_with("#{account.upcase}.")
        expect(decoded_token["sub"]).to eq("#{account.upcase}.#{user.upcase}")
      end
    end
    
    context "when organization is provided" do
      let(:organization) { "org" }
      
      it "uses org-account format in the token" do
        token = subject.jwt_token
        decoded_token = JWT.decode(token, OpenSSL::PKey::RSA.new(private_key).public_key, true, { algorithm: 'RS256' })[0]
        
        expect(decoded_token["iss"]).to start_with("#{organization.upcase}-#{account.upcase}.")
        expect(decoded_token["sub"]).to eq("#{organization.upcase}-#{account.upcase}.#{user.upcase}")
      end
    end
  end
end