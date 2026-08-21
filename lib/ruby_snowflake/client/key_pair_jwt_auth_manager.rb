# frozen_string_literal: true

require "jwt"
require "openssl"
require "concurrent"

module RubySnowflake
  class Client
    class KeyPairJwtAuthManager
      # Snowflake judges `exp` against its own clock, so the last seconds of a token's window are
      # not ours to spend - re-sign once this much of its life has gone instead.
      REFRESH_RATIO = 0.8

      # One object so that a reader cannot see the token without the deadline that goes with it.
      CachedToken = Struct.new(:value, :refresh_at) do
        def fresh?(now)
          now < refresh_at
        end
      end

      # requires text of a PEM formatted RSA private key
      def initialize(organization, account, user, private_key, jwt_token_ttl, private_key_passphrase = nil)
        @organization = organization
        @account = account
        @user = user
        @private_key_pem = private_key
        @jwt_token_ttl = jwt_token_ttl
        @private_key_passphrase = private_key_passphrase

        @cached_token = Concurrent::AtomicReference.new(nil)
        @token_semaphore = Concurrent::Semaphore.new(1)
      end

      def jwt_token
        cached = @cached_token.get
        return cached.value if cached&.fresh?(Time.now.to_i)

        @token_semaphore.acquire do
          cached = @cached_token.get
          next cached.value if cached&.fresh?(Time.now.to_i)

          sign_token.tap { |token| @cached_token.set(token) }.value
        end
      end

      # For when Snowflake has refused the token we hold: the next request signs a new one.
      def expire_token!
        @cached_token.set(nil)
      end

      private
        def sign_token
          now = Time.now.to_i
          private_key = OpenSSL::PKey.read(@private_key_pem, @private_key_passphrase)

          payload = {
            :iss => "#{account_name}.#{@user.upcase}.#{public_key_fingerprint}",
            :sub => "#{account_name}.#{@user.upcase}",
            :iat => now,
            :exp => now + @jwt_token_ttl
          }

          CachedToken.new(JWT.encode(payload, private_key, "RS256"), now + refresh_interval)
        end

        def refresh_interval
          (@jwt_token_ttl * REFRESH_RATIO).floor
        end

        def account_name
          if @organization == nil || @organization == ""
            @account.upcase
          else
            "#{@organization.upcase}-#{@account.upcase}"
          end
        end

        def public_key_fingerprint
          return @public_key_fingerprint unless @public_key_fingerprint.nil?

          public_key_der = OpenSSL::PKey::RSA.new(@private_key_pem, @private_key_passphrase).public_key.to_der
          digest = OpenSSL::Digest::SHA256.new.digest(public_key_der)
          fingerprint = Base64.strict_encode64(digest)

          @public_key_fingerprint = "SHA256:#{fingerprint}"
        end
    end
  end
end
