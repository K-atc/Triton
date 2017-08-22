//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the BSD License.
*/

#ifndef TRITON_UNICORN_TRIGGER_H
#define TRITON_UNICORN_TRIGGER_H



//! The Tracer namespace
namespace tracer {
/*!
 *  \addtogroup tracer
 *  @{
 */

  //! The Unicorn namespace
  namespace unicorn {
  /*!
   *  \ingroup tracer
   *  \addtogroup pintool
   *  @{
   */

    //! \class Trigger Enable and disable the Pin's InsertCalls.
    class Trigger {
      protected:
        bool state;

      public:
        //! Constructor.
        Trigger();

        //! Switchs the trigger.
        void toggle();

        //! Returns true if the switch is ON, false otherwise.
        bool getState();

        //! Sets the state to true
        void enable(void);

        //! Sets the state to false
        void disable(void);

        //! Sets the state to flag
        void update(bool flag);
    };

  /*! @} End of unciron namespace */
  };
/*! @} End of tracer namespace */
};

#endif // TRITON_UNICORN_TRIGGER_H
