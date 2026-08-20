# frozen_string_literal: true

require "jwt"
require "openssl"
require "concurrent"

module RubySnowflake
  class Client
    class KeyPairJwtAuthManager
      # Sign a replacement once this much of the token's life has gone, rather than at the moment
      # it expires. Snowflake judges `exp` against its own clock, so a token handed over in the
      # last seconds of its window can arrive already expired, and Snowflake answers that with a
      # 401 that costs us the query it was carrying.
      REFRESH_RATIO = 0.8

      # The signed token and the point we stop using it, kept together so that no reader can see
      # one without the other.
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

      def auth_headers
        {
          "Authorization" => "Bearer #{jwt_token}",
          "X-Snowflake-Authorization-Token-Type" => "KEYPAIR_JWT"
        }
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

      # Throw away the token we hold, so the next request signs a new one. Snowflake has told us
      # this one is no good and re-sending it would only be refused again.
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
