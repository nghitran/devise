require 'devise/hooks/activatable'

module Devise
  module Models
    # Authenticable module. Holds common settings for authentication.
    #
    # == Configuration:
    #
    # You can overwrite configuration values by setting in globally in Devise,
    # using devise method or overwriting the respective instance method.
    #
    #   authentication_keys: parameters used for authentication. By default [:email].
    #
    #   http_authenticatable: if this model allows http authentication. By default true.
    #   It also accepts an array specifying the strategies that should allow http.
    #
    #   params_authenticatable: if this model allows authentication through request params. By default true.
    #   It also accepts an array specifying the strategies that should allow params authentication.
    #
    # == Active?
    #
    # Before authenticating an user and in each request, Devise checks if your model is active by
    # calling model.active?. This method is overwriten by other devise modules. For instance,
    # :confirmable overwrites .active? to only return true if your model was confirmed.
    #
    # You overwrite this method yourself, but if you do, don't forget to call super:
    #
    #   def active?
    #     super && special_condition_is_valid?
    #   end
    #
    # Whenever active? returns false, Devise asks the reason why your model is inactive using
    # the inactive_message method. You can overwrite it as well:
    #
    #   def inactive_message
    #     special_condition_is_valid? ? super : :special_condition_is_not_valid
    #   end
    #
    module Authenticatable
      extend ActiveSupport::Concern

      included do
        class_attribute :devise_modules, :instance_writer => false
        self.devise_modules ||= []
      end

      # Check if the current object is valid for authentication. This method and
      # find_for_authentication are the methods used in a Warden::Strategy to check
      # if a model should be signed in or not.
      #
      # However, you should not overwrite this method, you should overwrite active? and
      # inactive_message instead.
      def valid_for_authentication?
        if active?
          block_given? ? yield : true
        else
          inactive_message
        end
      end

      def active?
        true
      end

      def inactive_message
        :inactive
      end

      module ClassMethods
        Devise::Models.config(self, :authentication_keys, :http_authenticatable, :params_authenticatable)

        def params_authenticatable?(strategy)
          params_authenticatable.is_a?(Array) ?
            params_authenticatable.include?(strategy) : params_authenticatable
        end

        def http_authenticatable?(strategy)
          http_authenticatable.is_a?(Array) ?
            http_authenticatable.include?(strategy) : http_authenticatable
        end

        # Find first record based on conditions given (ie by the sign in form).
        # Overwrite to add customized conditions, create a join, or maybe use a
        # namedscope to filter records while authenticating.
        # Example:
        #
        #   def self.find_for_authentication(conditions={})
        #     conditions[:active] = true
        #     super
        #   end
        #
        def find_for_authentication(conditions)
          filter_auth_params(conditions)
          find(:first, :conditions => conditions)
        end

        # Find an initialize a record setting an error if it can't be found.
        def find_or_initialize_with_error_by(attribute, value, error=:invalid) #:nodoc:
          find_or_initialize_with_errors([attribute], { attribute => value }, error)
        end

        # Find or initialize a record with group of attributes based on a list of required attributes.
        def find_or_initialize_with_errors(required_attributes, attributes, error=:invalid) #:nodoc:
          attributes = if attributes.respond_to? :permit
            attributes.slice(*required_attributes).permit!.to_h.with_indifferent_access
          else
            attributes.with_indifferent_access.slice(*required_attributes)
          end
          attributes.delete_if { |key, value| value.blank? }

          if attributes.size == required_attributes.size
            record = find_for_authentication(attributes)
          end

          unless record
            record = new

            required_attributes.each do |key|
              value = attributes[key]
              record.send("#{key}=", value)
              record.errors.add(key, value.present? ? error : :blank)
            end
          end

          record
        end

        protected

        # Force keys to be string to avoid injection on mongoid related database.
        def filter_auth_params(conditions)
          conditions.each do |k, v|
            conditions[k] = v.to_s
          end
        end

        # Generate a token by looping and ensuring does not already exist.
        def generate_token(column)
          loop do
            token = Devise.friendly_token
            break token unless find(:first, :conditions => { column => token })
          end
        end
      end
    end
  end
end
